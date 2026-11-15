"""Rebuild the archive fixtures in this folder.

Run from the repository root with the archives extra installed:

    python tests/fixtures/archives/build_fixtures.py

The payloads are harmless strings. Names such as ``invoice.exe`` exist only
so the analyzer has something risky to report.
"""
from __future__ import annotations

import io
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import py7zr
import pycdlib
from cabarchive import CabArchive, CabFile

HERE = Path(__file__).resolve().parent
PAYLOAD = b"harmless test payload\n"
NOTE = b"Download the full statement at https://statement-portal.example/view\n"


def seven_zip(members: dict[str, bytes], password: str | None = None, hide_names: bool = True) -> bytes:
    stream = io.BytesIO()
    with py7zr.SevenZipFile(stream, "w", password=password, header_encryption=bool(password) and hide_names) as archive:
        for name, data in members.items():
            archive.writef(io.BytesIO(data), name)
    return stream.getvalue()


def zip_bytes(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return stream.getvalue()


def cab(members: dict[str, bytes]) -> bytes:
    archive = CabArchive()
    for name, data in members.items():
        archive[name] = CabFile(data)
    return archive.save(compress=True)


def iso(members: dict[str, bytes]) -> bytes:
    image = pycdlib.PyCdlib()
    image.new(joliet=3)
    for index, (name, data) in enumerate(members.items()):
        image.add_fp(io.BytesIO(data), len(data), f"/FILE{index}.;1", joliet_path="/" + name)
    out = io.BytesIO()
    image.write_fp(out)
    image.close()
    return out.getvalue()


def tar_gz(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _rar5_header(header_type: int, fields: bytes, data: bytes = b"") -> bytes:
    flags = 0x02 if data else 0
    body = _vint(header_type) + _vint(flags) + (_vint(len(data)) if data else b"") + fields
    sized = _vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(sized)) + sized + data


def rar5_stored(members: dict[str, bytes]) -> bytes:
    """Write a RAR5 archive with uncompressed members, which rarfile reads without unrar."""
    out = b"Rar!\x1a\x07\x01\x00" + _rar5_header(1, _vint(0))
    for name, data in members.items():
        encoded = name.encode()
        fields = (_vint(0x04) + _vint(len(data)) + _vint(0x20) + struct.pack("<I", zlib.crc32(data))
                  + _vint(0) + _vint(0) + _vint(len(encoded)) + encoded)
        out += _rar5_header(2, fields, data)
    return out + _rar5_header(5, _vint(0))


def rar5_header_encrypted() -> bytes:
    fields = _vint(0) + _vint(0x01) + bytes([15]) + b"\x11" * 16 + b"\x22" * 12
    return b"Rar!\x1a\x07\x01\x00" + _rar5_header(4, fields) + b"\x5a" * 64


def main() -> None:
    files = {
        "statement.7z": seven_zip({"statement.txt": NOTE, "invoice.pdf.exe": PAYLOAD}),
        "locked.7z": seven_zip({"invoice.exe": PAYLOAD}, password="infected"),
        "locked_names.7z": seven_zip({"invoice.exe": PAYLOAD}, password="infected", hide_names=False),
        "bomb.7z": seven_zip({"zeros.txt": b"\x00" * 20_000_000}),
        "statement.cab": cab({"statement.txt": NOTE, "setup.exe": PAYLOAD}),
        "statement.iso": iso({"statement.txt": NOTE, "invoice.lnk": PAYLOAD}),
        "statement.tar.gz": tar_gz({"docs/statement.txt": NOTE, "docs/run.js": PAYLOAD}),
        "bomb.tar.gz": tar_gz({"zeros.txt": b"\x00" * 20_000_000}),
        "statement.rar": rar5_stored({"statement.txt": NOTE, "invoice.scr": PAYLOAD}),
        "locked.rar": rar5_header_encrypted(),
    }
    inner_7z = seven_zip({"payload.exe": PAYLOAD})
    files["nested.cab"] = cab({"outer.zip": zip_bytes({"inner.7z": inner_7z, "readme.txt": b"see inner"})})
    for name, data in files.items():
        (HERE / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
