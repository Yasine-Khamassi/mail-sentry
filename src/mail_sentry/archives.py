"""Bounded archive inspection.

ZIP, TAR, and single file gzip, bzip2, and xz use the standard library.
7z, CAB, ISO, and RAR use optional packages from the ``archives`` extra
(py7zr, cabarchive, pycdlib, rarfile). When one is missing, the archive is
recorded and a note says which package would open it.

Every format goes through the same rails: a nesting depth limit, a total
expanded size budget, a compression ratio guard, a member count per archive,
and a member count across the whole attachment. Encrypted content is listed
by name and never read.
"""
from __future__ import annotations

import bz2
import io
import lzma
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from typing import Callable, Iterator

from .url_analysis import extract_urls

OFFICE_ARCHIVES = (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppsm", ".xlam", ".odt", ".ods", ".odp")
NESTED_EXTENSIONS = (".zip", ".7z", ".rar", ".cab", ".iso", ".img", ".tar", ".tgz", ".tbz2", ".txz", ".gz", ".bz2", ".xz") + OFFICE_ARCHIVES
TEXT_MEMBERS = (".xml", ".rels", ".txt", ".html", ".htm", ".svg", ".url", ".csv", ".js", ".vbs", ".hta", ".ps1", ".bat", ".cmd")
EXTENSION_KINDS = (
    ((".tar.gz", ".tgz", ".gz"), "gzip"), ((".tar.bz2", ".tbz2", ".bz2"), "bzip2"), ((".tar.xz", ".txz", ".xz"), "xz"),
    ((".zip",) + OFFICE_ARCHIVES, "zip"), ((".7z",), "7z"), ((".rar",), "rar"), ((".cab",), "cab"), ((".iso", ".img"), "iso"), ((".tar",), "tar"),
)
EXTRA_PACKAGES = {"7z": "py7zr", "cab": "cabarchive", "iso": "pycdlib", "rar": "rarfile"}
SNIFF_LIMIT = 1_000_000
CHUNK = 1 << 20
CAB_BLOCK_MAX = 0xFFFF


class MissingDependency(Exception):
    pass


class EncryptedContainer(Exception):
    pass


class LimitReached(Exception):
    pass


@dataclass
class Member:
    name: str
    size: int | None
    compressed: int | None = None
    encrypted: bool = False
    is_dir: bool = False
    read: Callable[[int], bytes] | None = None
    unreadable: str = ""


def archive_kind(data: bytes, name: str = "") -> str | None:
    """Identify an archive by magic bytes, then by name."""
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if data.startswith(b"MSCF"):
        return "cab"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    lower = name.lower()
    for extensions, kind in EXTENSION_KINDS:
        if lower.endswith(extensions):
            return kind
    return None


def rar_headers_encrypted(data: bytes) -> bool:
    """True for RAR5 archives whose first header is an archive encryption header."""
    if not data.startswith(b"Rar!\x1a\x07\x01\x00"):
        return False
    position = 8 + 4  # signature, header CRC32
    values = []
    for _ in range(2):  # header size, header type (both variable length integers)
        value, shift = 0, 0
        while position < len(data) and shift < 64:
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        values.append(value)
    return len(values) == 2 and values[1] == 4


# ------------------------------------------------------------------ formats

def _zip_members(data: bytes, scan: "ArchiveScan") -> Iterator[Member]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, EOFError) as exc:
        raise ValueError("not a readable ZIP container") from exc
    with archive:
        for info in entries:
            def read(limit: int, info=info) -> bytes:
                with archive.open(info) as stream:
                    return stream.read(limit + 1)
            yield Member(info.filename, info.file_size, info.compress_size, bool(info.flag_bits & 0x1), info.is_dir(), read)


def _bounded_decompress(data: bytes, kind: str, scan: "ArchiveScan") -> bytes:
    if kind == "gzip":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif kind == "bzip2":
        decoder = bz2.BZ2Decompressor()
    else:
        decoder = lzma.LZMADecompressor()
    chunks: list[bytes] = []
    total = 0
    pending = data
    try:
        while True:
            chunk = decoder.decompress(pending, CHUNK)
            if kind == "gzip":
                pending = decoder.unconsumed_tail
                done = decoder.eof or (not pending and not chunk)
            else:
                pending = b""
                done = decoder.eof or (decoder.needs_input and not chunk)
            total += len(chunk)
            chunks.append(chunk)
            if total > 1_000_000 and total > scan.max_ratio * max(len(data), 1):
                raise LimitReached(f"compression ratio above {scan.max_ratio}, not expanded")
            if total > scan.bytes_left:
                raise LimitReached("archive expanded size limit reached")
            if done:
                break
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        raise ValueError(f"not a readable {kind} stream") from exc
    return b"".join(chunks)


def _compressed_members(data: bytes, scan: "ArchiveScan", kind: str, name: str) -> Iterator[Member]:
    raw = _bounded_decompress(data, kind, scan)
    if len(raw) > 262 and raw[257:262] == b"ustar":
        yield from _tar_members(raw, scan)
        return
    inner = name.rsplit("/", 1)[-1]
    for suffix in (".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"):
        if inner.lower().endswith(suffix):
            inner = inner[: -len(suffix)] + (".tar" if suffix.startswith(".t") else "")
            break
    yield Member(inner or "decompressed", len(raw), len(data), read=lambda limit: raw[: limit + 1])


def _tar_members(data: bytes, scan: "ArchiveScan") -> Iterator[Member]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
        raise ValueError("not a readable TAR container") from exc
    with archive:
        try:
            for info in archive:
                def read(limit: int, info=info) -> bytes:
                    stream = archive.extractfile(info)
                    return stream.read(limit + 1) if stream else b""
                yield Member(info.name, info.size if info.isfile() else 0, None, False, info.isdir(), read if info.isfile() else None)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise ValueError("TAR container is truncated or corrupt") from exc


def _sevenzip_members(data: bytes, scan: "ArchiveScan") -> Iterator[Member]:
    try:
        import py7zr  # type: ignore
        from py7zr.io import BytesIOFactory  # type: ignore
    except ImportError as exc:
        raise MissingDependency("7z contents not inspected: install mail-sentry[archives] (py7zr)") from exc
    try:
        archive = py7zr.SevenZipFile(io.BytesIO(data), mode="r")
    except py7zr.exceptions.PasswordRequired as exc:
        raise EncryptedContainer("7z archive has encrypted headers") from exc
    except Exception as exc:  # py7zr raises many types on malformed input
        raise ValueError(f"not a readable 7z container ({type(exc).__name__})") from exc
    with archive:
        encrypted = archive.needs_password()
        entries = archive.list()
        total = sum(entry.uncompressed or 0 for entry in entries)
        if total > 1_000_000 and total > scan.max_ratio * max(len(data), 1):
            raise LimitReached(f"compression ratio above {scan.max_ratio}, not expanded")

        def read(limit: int, filename: str) -> bytes:
            archive.reset()
            factory = BytesIOFactory(limit + 1)
            archive.extract(targets=[filename], factory=factory)
            product = factory.products.get(filename)
            if product is None:
                return b""
            product.seek(0)
            return product.read(limit + 1)

        for entry in entries:
            yield Member(entry.filename, entry.uncompressed, entry.compressed, encrypted, entry.is_directory,
                         None if entry.is_directory else (lambda limit, name=entry.filename: read(limit, name)))


def _cab_decompression_bound(data: bytes) -> int:
    """Upper bound on bytes cabarchive would inflate, from the folder table."""
    if len(data) < 36 or not data.startswith(b"MSCF"):
        raise ValueError("not a CAB file")
    folders, _files, flags = struct.unpack_from("<HHH", data, 26)
    offset = 36
    folder_reserve = 0
    if flags & 0x4:
        header_reserve, folder_reserve, _data_reserve = struct.unpack_from("<HBB", data, 36)
        offset = 40 + header_reserve
    for flag in (0x1, 0x2):
        if flags & flag:
            for _ in range(2):
                end = data.find(b"\x00", offset)
                if end < 0:
                    raise ValueError("truncated CAB header")
                offset = end + 1
    blocks = 0
    for _ in range(folders):
        (count,) = struct.unpack_from("<H", data, offset + 4)
        blocks += count
        offset += 8 + folder_reserve
    return blocks * CAB_BLOCK_MAX


def _cab_members(data: bytes, scan: "ArchiveScan") -> Iterator[Member]:
    try:
        from cabarchive import CabArchive  # type: ignore
    except ImportError as exc:
        raise MissingDependency("CAB contents not inspected: install mail-sentry[archives] (cabarchive)") from exc
    try:
        bound = _cab_decompression_bound(data)
    except (struct.error, ValueError) as exc:
        raise ValueError("not a readable CAB container") from exc
    if bound > scan.bytes_left:
        raise LimitReached("archive expanded size limit reached")
    if bound > 1_000_000 and bound > scan.max_ratio * len(data):
        raise LimitReached(f"compression ratio above {scan.max_ratio}, not expanded")
    try:
        archive = CabArchive()
        archive.parse(data)
    except Exception as exc:  # cabarchive raises CorruptionError, NotSupportedError, struct errors
        raise ValueError(f"not a readable CAB container ({type(exc).__name__}: {exc})") from exc
    for name, entry in archive.items():
        content = bytes(entry.buf or b"")
        yield Member(name.replace("\\", "/"), len(content), None, read=lambda limit, content=content: content[: limit + 1])


def _iso_members(data: bytes, scan: "ArchiveScan") -> Iterator[Member]:
    try:
        import pycdlib  # type: ignore
    except ImportError as exc:
        raise MissingDependency("ISO contents not inspected: install mail-sentry[archives] (pycdlib)") from exc
    image = pycdlib.PyCdlib()
    try:
        image.open_fp(io.BytesIO(data))
        if image.has_udf():
            facade = "udf_path"
        elif image.has_joliet():
            facade = "joliet_path"
        elif image.has_rock_ridge():
            facade = "rr_path"
        else:
            facade = "iso_path"
        walked = list(image.walk(**{facade: "/"}))
    except Exception as exc:  # pycdlib raises PyCdlibException and others on bad images
        raise ValueError(f"not a readable ISO image ({type(exc).__name__})") from exc
    try:
        for directory, _dirs, files in walked:
            for filename in files:
                path = directory.rstrip("/") + "/" + filename
                display = path.lstrip("/")
                if facade == "iso_path":
                    display = display.split(";", 1)[0]
                try:
                    size = image.get_record(**{facade: path}).get_data_length()
                except Exception:
                    yield Member(display, None, unreadable="record could not be read")
                    continue
                if size > len(data):
                    yield Member(display, size, unreadable="claims more bytes than the image holds")
                    continue

                def read(limit: int, path=path) -> bytes:
                    out = io.BytesIO()
                    image.get_file_from_iso_fp(out, **{facade: path})
                    return out.getvalue()[: limit + 1]
                yield Member(display, size, read=read)
    finally:
        try:
            image.close()
        except Exception:
            pass


def _rar_members(data: bytes, scan: "ArchiveScan") -> Iterator[Member]:
    if rar_headers_encrypted(data):
        raise EncryptedContainer("RAR archive has encrypted headers")
    try:
        import rarfile  # type: ignore
    except ImportError as exc:
        raise MissingDependency("RAR contents not inspected: install mail-sentry[archives] (rarfile)") from exc
    try:
        archive = rarfile.RarFile(io.BytesIO(data))
        entries = archive.infolist()
    except rarfile.PasswordRequired as exc:
        raise EncryptedContainer("RAR archive has encrypted headers") from exc
    except Exception as exc:  # rarfile raises BadRarFile, NotRarFile, NeedFirstVolume and more
        raise ValueError(f"not a readable RAR container ({type(exc).__name__})") from exc
    if archive.needs_password() and not entries:
        raise EncryptedContainer("RAR archive has encrypted headers")
    with archive:
        for info in entries:
            def read(limit: int, info=info) -> bytes:
                try:
                    with archive.open(info) as stream:
                        return stream.read(limit + 1)
                except rarfile.RarCannotExec as exc:
                    raise MissingDependency("RAR member not extracted: unrar, unar, 7z, or bsdtar is not installed") from exc
            yield Member(info.filename, info.file_size, info.compress_size, info.needs_password(), info.is_dir(), read)


def _members(kind: str, data: bytes, scan: "ArchiveScan", name: str) -> Iterator[Member]:
    if kind == "zip":
        return _zip_members(data, scan)
    if kind == "tar":
        return _tar_members(data, scan)
    if kind in {"gzip", "bzip2", "xz"}:
        return _compressed_members(data, scan, kind, name)
    if kind == "7z":
        return _sevenzip_members(data, scan)
    if kind == "cab":
        return _cab_members(data, scan)
    if kind == "iso":
        return _iso_members(data, scan)
    if kind == "rar":
        return _rar_members(data, scan)
    raise ValueError(f"unsupported archive format {kind}")


# ------------------------------------------------------------------ scanner

class ArchiveScan:
    def __init__(self, limits: dict) -> None:
        self.entries_left = int(limits["max_archive_entries"])
        self.bytes_left = int(limits["max_archive_uncompressed_bytes"])
        self.max_depth = int(limits.get("max_archive_depth", 2))
        self.max_ratio = int(limits.get("max_compression_ratio", 100))
        self.per_archive = int(limits.get("max_archive_members", 200))
        self.members: list[str] = []
        self.urls: list[str] = []
        self.encrypted: list[str] = []
        self.limit_notes: list[str] = []
        self.formats: list[str] = []
        self.uninspected: list[str] = []
        self.macro = False

    def scan(self, data: bytes, depth: int = 0, prefix: str = "", name: str = "") -> bool:
        """Scan one container. Returns False when it could not be opened."""
        kind = archive_kind(data, name)
        label = prefix.rstrip("/") or name or "archive"
        if kind is None:
            self.limit_notes.append(f"{label}: not a recognized archive")
            return False
        self.formats.append(kind)
        count = 0
        try:
            for member in _members(kind, data, self, name or prefix.rstrip("/")):
                if count >= self.per_archive:
                    self.limit_notes.append(f"{label}: more than {self.per_archive} members, the rest were not listed")
                    break
                if self.entries_left <= 0:
                    self.limit_notes.append("archive entry limit reached")
                    return True
                count += 1
                self.entries_left -= 1
                self._member(member, depth, prefix)
        except EncryptedContainer as exc:
            self.encrypted.append(f"{label} ({exc})")
        except MissingDependency as exc:
            self.uninspected.append(kind)
            self.limit_notes.append(f"{label}: {exc}")
            return False
        except LimitReached as exc:
            self.limit_notes.append(f"{label}: {exc}")
        except ValueError as exc:
            self.limit_notes.append(f"{label}: {exc}")
            return False
        return True

    def _member(self, member: Member, depth: int, prefix: str) -> None:
        path = prefix + member.name
        self.members.append(path)
        lower = member.name.lower()
        if lower.endswith("vbaproject.bin"):
            self.macro = True
        if member.encrypted:
            self.encrypted.append(path)
            return
        if member.is_dir:
            return
        if member.unreadable:
            self.limit_notes.append(f"{path}: {member.unreadable}")
            return
        if member.read is None:
            return
        size = member.size
        if member.compressed and size and size / member.compressed > self.max_ratio and size > 1_000_000:
            self.limit_notes.append(f"{path}: compression ratio above {self.max_ratio}, not expanded")
            return
        named_nested = lower.endswith(NESTED_EXTENSIONS)
        is_text = lower.endswith(TEXT_MEMBERS)
        small = size is not None and size <= SNIFF_LIMIT
        if not (named_nested or is_text or small):
            return
        if size is not None and size > self.bytes_left:
            self.limit_notes.append("archive expanded size limit reached")
            return
        try:
            content = member.read(self.bytes_left)
        except MissingDependency as exc:
            self.limit_notes.append(f"{path}: {exc}")
            return
        except Exception as exc:  # third party readers on hostile data
            self.limit_notes.append(f"{path}: could not be read ({type(exc).__name__})")
            return
        if len(content) > self.bytes_left:
            self.limit_notes.append("archive expanded size limit reached")
            return
        self.bytes_left -= len(content)
        # Named archives may fall back to their extension; anything else
        # must carry archive magic bytes to be treated as nested.
        nested_kind = archive_kind(content, member.name) if named_nested else archive_kind(content)
        if nested_kind:
            if depth + 1 > self.max_depth:
                self.limit_notes.append(f"{path}: nested archive deeper than {self.max_depth} levels, not expanded")
                return
            self.scan(content, depth + 1, path + "/", member.name)
        elif is_text:
            self.urls.extend(extract_urls(content.decode("utf-8", "replace")))
