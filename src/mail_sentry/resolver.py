"""DNS access for the optional authentication checks.

Mail Sentry is offline by default. The analyzer receives one of three
resolvers:

* ``OfflineResolver`` answers nothing and says so. This is the default.
* ``StaticResolver`` answers from records you supply, for example a JSON
  snapshot taken by your gateway. It never touches the network.
* ``LiveResolver`` queries DNS through dnspython. It is used only when the
  caller asks for it (``--dns`` or ``--check-spf``).

Every resolver returns a list of text values. An empty list means the name
or record type does not exist. A temporary failure raises ``DnsTempError``.
"""
from __future__ import annotations

import json
from pathlib import Path

QTYPES = {"A", "AAAA", "MX", "PTR", "TXT", "SPF", "CNAME"}


class DnsTempError(Exception):
    """A lookup failed for a reason that might go away (timeout, SERVFAIL)."""


class DnsDisabled(Exception):
    """The analyzer is running offline and no record source was given."""


def _key(name: str) -> str:
    return name.strip().rstrip(".").lower()


class OfflineResolver:
    live = False

    def query(self, name: str, qtype: str) -> list[str]:
        raise DnsDisabled(f"DNS disabled; {qtype} {_key(name)} was not looked up")


class StaticResolver:
    """Answer lookups from a fixed record set.

    ``records`` maps a host name to an object of record type to values::

        {"sel._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=..."]},
         "example.com": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"], "MX": ["10 mx.example.com"]}}

    A name listed with the value ``"TEMPFAIL"`` for a type raises
    ``DnsTempError``, which lets tests and analysts model a broken zone.
    """

    live = False

    def __init__(self, records: dict) -> None:
        if not isinstance(records, dict):
            raise ValueError("DNS records must be a JSON object of host names")
        self.records: dict[str, dict[str, object]] = {}
        for name, types in records.items():
            if not isinstance(name, str) or not isinstance(types, dict):
                raise ValueError("DNS records must map host names to objects of record types")
            entry = {}
            for qtype, values in types.items():
                qtype = str(qtype).upper()
                if qtype not in QTYPES:
                    raise ValueError(f"unsupported DNS record type {qtype} for {name}")
                if values == "TEMPFAIL":
                    entry[qtype] = "TEMPFAIL"
                elif isinstance(values, list) and all(isinstance(v, str) for v in values):
                    entry[qtype] = list(values)
                else:
                    raise ValueError(f"DNS values for {name} {qtype} must be a list of strings or \"TEMPFAIL\"")
            self.records[_key(name)] = entry

    @classmethod
    def from_file(cls, path: str | Path) -> "StaticResolver":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot load DNS records from {path}: {exc}") from exc
        return cls(data)

    def query(self, name: str, qtype: str) -> list[str]:
        values = self.records.get(_key(name), {}).get(qtype.upper(), [])
        if values == "TEMPFAIL":
            raise DnsTempError(f"configured temporary failure for {qtype} {_key(name)}")
        return list(values)  # type: ignore[arg-type]


class LiveResolver:
    """Query DNS with dnspython. Only created when the caller opts in."""

    live = True

    def __init__(self, timeout: float = 5.0) -> None:
        try:
            import dns.exception  # type: ignore
            import dns.resolver  # type: ignore
        except ImportError as exc:
            raise ValueError("live DNS lookups need dnspython: pip install mail-sentry[auth]") from exc
        self._dns = dns
        self.timeout = timeout

    def query(self, name: str, qtype: str) -> list[str]:
        dns = self._dns
        try:
            answer = dns.resolver.resolve(_key(name), qtype, lifetime=self.timeout, search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsTempError(f"{qtype} {_key(name)}: {type(exc).__name__}") from exc
        values = []
        for rdata in answer:
            if qtype in {"TXT", "SPF"}:
                values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            elif qtype in {"A", "AAAA"}:
                values.append(rdata.address)
            elif qtype == "MX":
                values.append(f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True)}")
            else:
                values.append(rdata.target.to_text(omit_final_dot=True))
        return values
