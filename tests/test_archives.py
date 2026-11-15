from __future__ import annotations

import bz2
import importlib.util
import io
import lzma
import sys
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from mail_sentry.archives import ArchiveScan, archive_kind
from mail_sentry.attachment_analysis import analyze_attachment
from mail_sentry.config import load_rules

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "archives"
HAS = {name: importlib.util.find_spec(name) is not None for name in ("py7zr", "cabarchive", "pycdlib", "rarfile")}


def analyze(name: str, rules: dict | None = None):
    return analyze_attachment(name, "application/octet-stream", (FIXTURES / name).read_bytes(), rules or load_rules())


def rule_names(signals):
    return {signal["rule"] for signal in signals}


def make_zip(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return stream.getvalue()


def make_tar(members: dict[str, bytes], mode: str = "w") -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode=mode) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class DetectionTests(unittest.TestCase):
    def test_magic_wins_over_name(self):
        self.assertEqual(archive_kind(make_zip({"a.txt": b"x"}), "photo.7z"), "zip")
        self.assertEqual(archive_kind(make_tar({"a.txt": b"x"})), "tar")
        self.assertEqual(archive_kind(b"MSCF" + b"\x00" * 40), "cab")

    def test_name_is_the_fallback(self):
        self.assertEqual(archive_kind(b"junk", "x.tar.gz"), "gzip")
        self.assertIsNone(archive_kind(b"junk", "x.txt"))


class TarTests(unittest.TestCase):
    def test_tar_gz_fixture(self):
        report, signals = analyze("statement.tar.gz")
        self.assertEqual(report["archive_members"], ["docs/statement.txt", "docs/run.js"])
        self.assertIn("archive_dangerous_member", rule_names(signals))
        self.assertIn("embedded_attachment_url", rule_names(signals))

    def test_plain_tar_bz2_and_xz(self):
        tar = make_tar({"run.vbs": b"x"})
        for name, data in (("a.tar", tar), ("a.tar.bz2", bz2.compress(tar)), ("a.tar.xz", lzma.compress(tar))):
            with self.subTest(name=name):
                report, signals = analyze_attachment(name, "application/octet-stream", data, load_rules())
                self.assertIn("run.vbs", report["archive_members"])
                self.assertIn("archive_dangerous_member", rule_names(signals))

    def test_single_file_gzip_is_one_member(self):
        import gzip
        report, _signals = analyze_attachment("notes.txt.gz", "application/gzip", gzip.compress(b"https://drop.example/a"), load_rules())
        self.assertEqual(report["archive_members"], ["notes.txt"])

    def test_gzip_bomb_is_refused(self):
        report, _signals = analyze("bomb.tar.gz")
        self.assertEqual(report["archive_members"], [])
        self.assertTrue(any("compression ratio" in note for note in report["archive_notes"]))

    def test_truncated_tar_gz_does_not_crash(self):
        data = (FIXTURES / "statement.tar.gz").read_bytes()[:40]
        report, _signals = analyze_attachment("cut.tar.gz", "application/gzip", data, load_rules())
        self.assertIn("archive inspection limit reached", report["flags"])


@unittest.skipUnless(HAS["py7zr"], "py7zr not installed")
class SevenZipTests(unittest.TestCase):
    def test_members_and_text_are_inspected(self):
        report, signals = analyze("statement.7z")
        self.assertEqual(report["archive_format"], "7z")
        self.assertIn("invoice.pdf.exe", report["archive_members"])
        self.assertIn("archive_dangerous_member", rule_names(signals))
        self.assertIn("embedded_attachment_url", rule_names(signals))

    def test_header_encrypted_archive_is_skipped(self):
        report, signals = analyze("locked.7z")
        self.assertEqual(report["archive_members"], [])
        self.assertIn("encrypted_archive", rule_names(signals))

    def test_encrypted_content_with_visible_names(self):
        report, signals = analyze("locked_names.7z")
        self.assertEqual(report["archive_members"], ["invoice.exe"])
        self.assertEqual({"encrypted_archive", "archive_dangerous_member"}, rule_names(signals))

    def test_bomb_is_refused(self):
        report, _signals = analyze("bomb.7z")
        self.assertEqual(report["archive_members"], [])
        self.assertTrue(any("compression ratio" in note for note in report["archive_notes"]))


@unittest.skipUnless(HAS["cabarchive"], "cabarchive not installed")
class CabTests(unittest.TestCase):
    def test_members_are_listed(self):
        report, signals = analyze("statement.cab")
        self.assertEqual(sorted(report["archive_members"]), ["setup.exe", "statement.txt"])
        self.assertIn("archive_dangerous_member", rule_names(signals))

    def test_declared_blocks_beyond_budget_are_not_inflated(self):
        rules = load_rules()
        rules["limits"]["max_archive_uncompressed_bytes"] = 1000
        report, _signals = analyze("statement.cab", rules)
        self.assertTrue(any("expanded size limit" in note for note in report["archive_notes"]))

    def test_corrupt_cab_does_not_crash(self):
        report, _signals = analyze_attachment("x.cab", "application/vnd.ms-cab-compressed", b"MSCF" + b"\xff" * 60, load_rules())
        self.assertIn("archive inspection limit reached", report["flags"])


@unittest.skipUnless(HAS["pycdlib"], "pycdlib not installed")
class IsoTests(unittest.TestCase):
    def test_members_are_listed_with_joliet_names(self):
        report, signals = analyze("statement.iso")
        self.assertEqual(report["detected_type"], "iso")
        self.assertEqual(sorted(report["archive_members"]), ["invoice.lnk", "statement.txt"])
        self.assertIn("archive_dangerous_member", rule_names(signals))
        self.assertIn("embedded_attachment_url", rule_names(signals))


@unittest.skipUnless(HAS["rarfile"], "rarfile not installed")
class RarTests(unittest.TestCase):
    def test_stored_members_are_read_without_unrar(self):
        report, signals = analyze("statement.rar")
        self.assertEqual(report["archive_members"], ["statement.txt", "invoice.scr"])
        self.assertIn("archive_dangerous_member", rule_names(signals))
        self.assertIn("embedded_attachment_url", rule_names(signals))

    def test_missing_extractor_is_noted_not_raised(self):
        import rarfile
        with mock.patch.object(rarfile.RarFile, "open", side_effect=rarfile.RarCannotExec("no tool")):
            report, signals = analyze("statement.rar")
        self.assertIn("invoice.scr", report["archive_members"])
        self.assertTrue(any("not installed" in note for note in report["archive_notes"]))


class RarWithoutLibraryTests(unittest.TestCase):
    def test_header_encryption_is_detected_without_rarfile(self):
        report, signals = analyze("locked.rar")
        self.assertIn("encrypted_archive", rule_names(signals))


@unittest.skipUnless(all(HAS[name] for name in ("py7zr", "cabarchive")), "py7zr and cabarchive not installed")
class NestedTests(unittest.TestCase):
    def test_7z_inside_zip_inside_cab(self):
        report, signals = analyze("nested.cab")
        self.assertIn("outer.zip/inner.7z/payload.exe", report["archive_members"])
        self.assertEqual(report["nested_archive_formats"], ["zip", "7z"])
        self.assertIn("archive_dangerous_member", rule_names(signals))

    def test_depth_limit_stops_before_the_7z(self):
        rules = load_rules()
        rules["limits"]["max_archive_depth"] = 1
        report, _signals = analyze("nested.cab", rules)
        self.assertNotIn("outer.zip/inner.7z/payload.exe", report["archive_members"])
        self.assertTrue(any("deeper than 1" in note for note in report["archive_notes"]))

    def test_renamed_nested_archive_is_found_by_magic(self):
        inner = (FIXTURES / "statement.7z").read_bytes()
        outer = make_zip({"scan.pdf": inner})
        report, _signals = analyze_attachment("outer.zip", "application/zip", outer, load_rules())
        self.assertIn("scan.pdf/invoice.pdf.exe", report["archive_members"])


class LimitTests(unittest.TestCase):
    def test_per_archive_member_cap(self):
        rules = load_rules()
        rules["limits"]["max_archive_members"] = 3
        data = make_zip({f"f{i}.txt": b"x" for i in range(10)})
        report, _signals = analyze_attachment("many.zip", "application/zip", data, rules)
        self.assertEqual(len(report["archive_members"]), 3)
        self.assertTrue(any("more than 3 members" in note for note in report["archive_notes"]))

    def test_global_entry_cap_spans_nested_archives(self):
        scan = ArchiveScan({**load_rules()["limits"], "max_archive_entries": 2})
        scan.scan(make_zip({"inner.zip": make_zip({"a.txt": b"1", "b.txt": b"2"})}), name="outer.zip")
        self.assertEqual(len(scan.members), 2)
        self.assertIn("archive entry limit reached", scan.limit_notes)


class MissingLibraryTests(unittest.TestCase):
    def test_missing_extra_is_reported(self):
        with mock.patch.dict(sys.modules, {"py7zr": None, "py7zr.io": None}):
            report, signals = analyze("statement.7z")
        self.assertEqual(report["archive_members"], [])
        self.assertIn("archive encryption status not inspected for this format", report["flags"])
        self.assertTrue(any("mail-sentry[archives]" in note for note in report["archive_notes"]))
        self.assertNotIn("encrypted_archive", rule_names(signals))


if __name__ == "__main__":
    unittest.main()
