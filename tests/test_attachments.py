from __future__ import annotations

import io
import os
import unittest
import zipfile

from mail_sentry.attachment_analysis import analyze_attachment
from mail_sentry.config import load_rules

RLO = chr(0x202E)


def rule_names(signals):
    return {signal["rule"] for signal in signals}


def make_zip(members: dict[str, bytes], encrypt: set[str] = frozenset()) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    raw = bytearray(stream.getvalue())
    # Mark selected members as encrypted by setting general purpose bit 0 in
    # both the local and central directory headers. Content is not readable,
    # which is exactly what an analyzer sees with a password-protected entry.
    for name in encrypt:
        encoded = name.encode()
        for signature, flag_offset, name_offset in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
            start = 0
            while (start := raw.find(signature, start)) != -1:
                if raw[start + name_offset:start + name_offset + len(encoded)] == encoded:
                    raw[start + flag_offset] |= 1
                start += 4
    return bytes(raw)


class NameTests(unittest.TestCase):
    def test_padded_double_extension(self):
        _report, signals = analyze_attachment("invoice.pdf          .exe", "application/octet-stream", b"MZ", load_rules())
        self.assertIn("double_extension", rule_names(signals))

    def test_right_to_left_override_name(self):
        name = "invoice" + RLO + "fdp.exe"
        report, signals = analyze_attachment(name, "application/octet-stream", b"MZ", load_rules())
        self.assertIn("filename_spoofing", rule_names(signals))
        self.assertIn("dangerous_attachment", rule_names(signals))

    def test_trailing_dot_does_not_hide_extension(self):
        _report, signals = analyze_attachment("setup.exe.", "application/octet-stream", b"MZ", load_rules())
        self.assertIn("dangerous_attachment", rule_names(signals))

    def test_plain_pdf_is_quiet(self):
        _report, signals = analyze_attachment("report.pdf", "application/pdf", b"%PDF-1.7\n" + b"x" * 100, load_rules())
        self.assertEqual(signals, [])


class ContentTests(unittest.TestCase):
    def test_executable_named_as_document(self):
        report, signals = analyze_attachment("scan.pdf", "application/pdf", b"MZ\x90\x00" + b"\x00" * 64, load_rules())
        self.assertEqual(report["detected_type"], "pe")
        self.assertIn("type_mismatch", rule_names(signals))

    def test_compressed_formats_skip_entropy_signal(self):
        random_bytes = os.urandom(20000)
        _report, signals = analyze_attachment("photo.jpg", "image/jpeg", b"\xff\xd8\xff" + random_bytes, load_rules())
        self.assertNotIn("high_entropy_attachment", rule_names(signals))
        _report, signals = analyze_attachment("blob.dat", "application/octet-stream", random_bytes, load_rules())
        self.assertIn("high_entropy_attachment", rule_names(signals))

    def test_legacy_office_vba_project(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + "_VBA_PROJECT".encode("utf-16-le")
        _report, signals = analyze_attachment("budget.xls", "application/vnd.ms-excel", data, load_rules())
        self.assertIn("macro_attachment", rule_names(signals))

    def test_docx_with_vba_project_is_flagged(self):
        data = make_zip({"word/document.xml": b"<w/>", "word/vbaProject.bin": b"\x00"})
        _report, signals = analyze_attachment("letter.docx", "application/octet-stream", data, load_rules())
        self.assertIn("macro_attachment", rule_names(signals))

    def test_html_attachment_with_password_form(self):
        page = b'<form action="https://collect.example/"><input type="password" name="p"></form>'
        report, signals = analyze_attachment("Remittance.html", "text/html", page, load_rules())
        self.assertIn("html_attachment", rule_names(signals))
        self.assertIn("credential_form", rule_names(signals))


class ArchiveTests(unittest.TestCase):
    def test_dangerous_member_names_are_reported(self):
        data = make_zip({"docs/readme.txt": b"hello", "docs/invoice.pdf.lnk": b"L"})
        report, signals = analyze_attachment("docs.zip", "application/zip", data, load_rules())
        self.assertIn("archive_dangerous_member", rule_names(signals))
        self.assertIn("docs/invoice.pdf.lnk", report["archive_members"])

    def test_nested_archive_is_scanned_within_depth(self):
        inner = make_zip({"payload.js": b"https://drop.example/a"})
        outer = make_zip({"inner.zip": inner})
        report, signals = analyze_attachment("outer.zip", "application/zip", outer, load_rules())
        self.assertIn("inner.zip/payload.js", report["archive_members"])
        self.assertIn("archive_dangerous_member", rule_names(signals))

    def test_nesting_beyond_depth_is_not_expanded(self):
        rules = load_rules()
        rules["limits"]["max_archive_depth"] = 1
        level3 = make_zip({"deep.exe": b"MZ"})
        level2 = make_zip({"l3.zip": level3})
        level1 = make_zip({"l2.zip": level2})
        report, signals = analyze_attachment("l1.zip", "application/zip", level1, rules)
        self.assertNotIn("l2.zip/l3.zip/deep.exe", report["archive_members"])
        self.assertIn("archive inspection limit reached", report["flags"])

    def test_high_compression_ratio_member_is_not_expanded(self):
        data = make_zip({"bomb.txt": b"0" * 5_000_000})
        report, _signals = analyze_attachment("bomb.zip", "application/zip", data, load_rules())
        self.assertIn("archive inspection limit reached", report["flags"])
        self.assertTrue(any("compression ratio" in note for note in report["archive_notes"]))

    def test_encrypted_member_names_are_still_checked(self):
        data = make_zip({"invoice.exe": b"MZ" * 50}, encrypt={"invoice.exe"})
        _report, signals = analyze_attachment("secure.zip", "application/zip", data, load_rules())
        self.assertIn("encrypted_archive", rule_names(signals))
        self.assertIn("archive_dangerous_member", rule_names(signals))

    def test_zip_disguised_by_extension_is_detected(self):
        data = make_zip({"run.vbs": b"x"})
        report, signals = analyze_attachment("photo.jpg", "image/jpeg", data, load_rules())
        self.assertIn("type_mismatch", rule_names(signals))
        self.assertIn("archive_dangerous_member", rule_names(signals))

    def test_truncated_zip_does_not_crash(self):
        data = make_zip({"a.txt": b"https://x.example " * 50})[:-30]
        report, _signals = analyze_attachment("cut.zip", "application/zip", data, load_rules())
        self.assertIn("archive inspection limit reached", report["flags"])


if __name__ == "__main__":
    unittest.main()
