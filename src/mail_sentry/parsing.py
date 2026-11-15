from __future__ import annotations

import mimetypes
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path


def parse_message(path: Path, limits: dict) -> Message:
    return read_message(path, limits)[0]


def read_message(path: Path, limits: dict) -> tuple[Message, bytes | None]:
    """Parse the input and return it with its raw bytes.

    Raw bytes are needed for DKIM verification. They are only available for
    .eml input; an Outlook .msg does not keep the original MIME bytes.
    """
    raw: bytes | None = None
    if path.suffix.lower() not in {".eml", ".msg"}:
        raise ValueError("input must have an .eml or .msg extension")
    maximum = int(limits["max_input_bytes"])
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot read input file: {exc}") from exc
    if size > maximum:
        raise ValueError(f"input file exceeds configured limit of {maximum} bytes")
    if path.suffix.lower() == ".eml":
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError(f"input file exceeds configured limit of {maximum} bytes")
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw)
        except RecursionError as exc:
            raise ValueError("message MIME nesting exceeds parser safety limits") from exc
    else:
        try:
            import extract_msg  # type: ignore
        except ImportError as exc:
            raise ValueError("MSG support requires optional dependency: pip install mail-sentry[msg]") from exc
        try:
            msg = extract_msg.Message(str(path))
        except Exception as exc:
            raise ValueError(f"cannot parse Outlook MSG file: {exc}") from exc
        try:
            message = _normalize_msg(msg)
        except Exception as exc:
            raise ValueError(f"cannot normalize Outlook MSG content: {exc}") from exc
        finally:
            try:
                msg.close()
            except Exception:
                pass
    _enforce_part_limit(message, int(limits["max_mime_parts"]))
    return message, raw


def _normalize_msg(msg: object) -> Message:
    """Copy a MSG into a standard EmailMessage before closing its OLE handle."""
    try:
        # This public extract-msg API preserves its own MIME header/body and
        # attachment normalization rules for standard Outlook messages.
        message = msg.asEmailMessage()  # type: ignore[attr-defined]
        if isinstance(message, Message):
            return message
    except Exception:
        # Fall back for malformed body encodings or attachment types that the
        # library cannot convert, while still preserving inspectable standard
        # attachments and both available body variants.
        pass

    normalized = EmailMessage(policy=policy.default)
    header = getattr(msg, "header", None)
    if isinstance(header, Message):
        for name, value in header.items():
            lowered = name.lower()
            if lowered in {"content-type", "content-transfer-encoding", "mime-version"}:
                continue
            if normalized.get(name) is None:
                normalized[name] = str(value)
    else:
        for name, value in (("Subject", getattr(msg, "subject", None)), ("From", getattr(msg, "sender", None)), ("To", getattr(msg, "to", None))):
            if value:
                normalized[name] = str(value)

    plain = getattr(msg, "body", None)
    html_body = getattr(msg, "htmlBody", None)
    if isinstance(plain, bytes):
        plain = plain.decode("utf-8", "replace")
    normalized.set_content(str(plain or ""))
    if html_body:
        if isinstance(html_body, bytes):
            html_body = html_body.decode("utf-8", "replace")
        normalized.add_alternative(str(html_body), subtype="html")

    for attachment in getattr(msg, "attachments", []) or []:
        data = getattr(attachment, "data", None)
        if not isinstance(data, bytes):
            as_bytes = getattr(attachment, "asBytes", None)
            data = as_bytes if isinstance(as_bytes, bytes) else None
        if data is None:
            # Web reference and unsupported custom attachments do not contain
            # local payload bytes and must never trigger network retrieval.
            continue
        filename = getattr(attachment, "longFilename", None) or getattr(attachment, "shortFilename", None)
        if not filename:
            get_filename = getattr(attachment, "getFilename", None)
            filename = get_filename() if callable(get_filename) else "unnamed-attachment"
        content_type = getattr(attachment, "mimetype", None) or mimetypes.guess_type(str(filename))[0] or "application/octet-stream"
        maintype, _, subtype = content_type.partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        normalized.add_attachment(data, maintype=maintype, subtype=subtype, filename=str(filename))
    return normalized


def iter_parts(message: Message, max_parts: int):
    """Iterate MIME parts iteratively so adversarial nesting cannot recurse."""
    stack = [message]
    count = 0
    while stack:
        part = stack.pop()
        count += 1
        if count > max_parts:
            raise ValueError(f"message exceeds configured MIME part limit of {max_parts}")
        yield part
        payload = part.get_payload()
        if isinstance(payload, list):
            stack.extend(reversed(payload))


def _enforce_part_limit(message: Message, max_parts: int) -> None:
    for _ in iter_parts(message, max_parts):
        pass


def decode_text(part: Message) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except (LookupError, UnicodeError, KeyError):
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, "replace")
        except LookupError:
            return payload.decode("utf-8", "replace")
