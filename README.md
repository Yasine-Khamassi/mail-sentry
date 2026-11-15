# Mail Sentry

Mail Sentry triages suspicious email for a SOC. Point it at an `.eml` or Outlook `.msg` file and it returns a JSON report: a score, a verdict, and every rule that fired with the evidence behind it.

It runs offline by default. It never opens URLs, queries reputation services, or executes attachments, and it resolves no DNS names unless you pass `--dns` or `--check-spf`. You can run it against live phishing samples on an isolated host.

## What it checks

**Authentication, verified locally**
* DKIM signatures checked cryptographically against the raw message (dkimpy)
* SPF evaluated for the client IP your gateway recorded in its `Received` header (pyspf, opt in)
* DMARC alignment computed only from those two local results, never from `Authentication-Results` claims
* Results use the RFC 8601 words (`pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`), so a missing key or a DNS outage is never reported as a forgery

**Headers**
* SPF, DKIM, and DMARC results your own gateway wrote, read only inside its trust boundary (see [Authentication trust](#authentication-trust))
* From, Return-Path, and Reply-To compared by organizational domain, so `mail.shop.example` and `bounces.shop.example` do not count as a mismatch
* Display names that carry a different address (`"ceo@brand.example" <x@other.example>`) or name a brand the sender address does not belong to
* Sender domains that imitate a brand (`micros0ft-login.example`)
* Duplicate or unparseable From headers, odd Received chains, and scripted X-Mailer values

**HTML and text**
* Password fields, with the form action they post to
* Scripts, any `on*` event handler, `javascript:` URLs, iframes, `srcdoc` documents (parsed too), and meta refresh redirects
* Hidden content that matters: large hidden text blocks, links inside hidden elements, zero width characters inside words, and bidirectional override characters. A short hidden preheader on its own is not flagged.
* Link text that shows one domain while the link goes to another
* Lure language in nine languages (see [Lure dictionaries](#lure-dictionaries)). Hidden text is not used for these.

**URLs**
* Normalized the way a browser reads them: tabs and invisible characters removed, backslashes treated as slashes, percent escapes in the host decoded, IDN converted to punycode, dot segments resolved
* IP hosts, including integer, hex, and octal IPv4 forms such as `http://3232235777/`
* User info before the host (`https://microsoft.com@198.51.100.25/`)
* Punycode hosts, with a stronger finding when a label mixes Latin and Cyrillic or Greek letters
* Brand lookalikes using a homoglyph skeleton (digit swaps, `rn` for `m`, common Cyrillic and Greek confusables) plus edit distance and brand tokens
* `data:` URIs that render HTML or SVG, known shorteners, and high abuse TLDs
* Obfuscation in the scheme or host. Ordinary percent encoding in query strings is not flagged.
* Wrapper links (`?url=`, `?u=`, `#url=` and similar) are decoded to show which URL they name

**Attachments**
* SHA 256, size, entropy, and the real file type from magic bytes
* Executables or containers named as documents (`scan.pdf` that starts with `MZ`)
* Risky extensions, padded or deceptive double extensions, right to left override tricks, and trailing dots
* Macro formats, VBA projects inside `.docx` files, and VBA in legacy OLE Office files
* HTML and SVG attachments, including password forms inside them
* Archives: ZIP, Office, TAR, gzip, bzip2, and xz with the standard library; 7z, CAB, ISO, and RAR with the `archives` extra. Every member name is checked, text members are searched for URLs, and nested archives are opened up to a depth limit. Nesting is found by magic bytes, so a 7z renamed to `.pdf` inside a ZIP inside a CAB is still opened.
* Encrypted archives and members (ZIP, 7z, RAR, including encrypted headers) are reported by name and never read
* High entropy only for file types that are not compressed by design, so ordinary JPEG, PDF, and ZIP files do not trip it

## Install and run

Python 3.10 or later. The core uses only the standard library. Optional extras add features:

| Extra | Packages | Adds |
| --- | --- | --- |
| `auth` | dkimpy, pyspf, dnspython | DKIM verification, SPF, DMARC alignment |
| `archives` | py7zr, cabarchive, pycdlib, rarfile | 7z, CAB, ISO, and RAR contents |
| `lang` | langdetect | better language detection for lure scoring |
| `msg` | extract-msg | Outlook `.msg` input |

```powershell
python -m pip install -e ".[auth,archives,lang,msg]"
mail-sentry samples/phishing.eml --pretty
mail-sentry message.msg --output report.json --pretty
```

Without the console script:

```powershell
python -m mail_sentry.cli samples/suspicious.eml --pretty
```

Flags:

| Flag | Effect |
| --- | --- |
| `--rules PATH` | Overlay a JSON rules file on the defaults |
| `--dns-records PATH` | Answer DNS questions from a JSON snapshot. Stays offline. |
| `--dns` | Allow live DNS lookups for DKIM keys and the DMARC policy |
| `--check-spf` | Evaluate SPF. Uses live DNS unless `--dns-records` is given. |
| `-o`, `--output PATH` | Write the report to a file instead of stdout |
| `--pretty` | Indent the JSON |

Exit codes: `0` when a report was written, `2` for input or configuration errors, `3` when a malformed message could not be analyzed.

RAR members stored without compression are read directly. Compressed RAR members need `unrar`, `unar`, `7z`, or `bsdtar` on the path; without one, member names are still checked and the report says the content was not extracted.

## Example output

Abbreviated report for `samples/phishing.eml`:

```json
{
  "schema_version": "2.1",
  "verdict": "high_confidence_phishing",
  "score": 100,
  "signals": [
    {"rule": "credential_form", "weight": 28, "count": 1,
     "detail": "HTML message contains a form with a password field",
     "evidence": ["form action: https://signin-microsoft.example/collect"]},
    {"rule": "sender_lookalike", "weight": 22, "count": 1,
     "detail": "Sender domain resembles a trusted brand domain (microsoft.com)",
     "evidence": ["micros0ft-login.example"]}
  ],
  "auth": {
    "dkim": {"result": "none", "verified": false, "d_tag": null, "s_tag": null, "errors": []},
    "spf": {"result": null, "checked": false, "ip": null, "from": "bulk@send-service.example",
            "errors": ["SPF not checked (enable with --check-spf)"]},
    "dmarc": {"result": "neutral", "policy": null,
              "alignment": {"dkim": false, "spf": null, "adkim": "r", "aspf": "r"}}
  },
  "language": {"detected": "en", "confidence": 1.0, "source": "body", "scanned": ["ar", "de", "en", "..."]},
  "urls": [
    {"url": "https://microsoft.com@198.51.100.25/secure", "host": "198.51.100.25",
     "flags": ["userinfo before hostname", "IP literal"], "wrapped_targets": []}
  ],
  "attachments": [],
  "parse_defects": {}
}
```

The full report also includes decoded headers, ignored Authentication-Results headers with the reason each was ignored, every DKIM signature with its own result, lure matches by language and category, normalized URLs, archive member lists, and analysis notes.

## Scoring

Signals are grouped by rule. Each rule adds its weight once, no matter how many times it fired; the report still shows the count and up to five pieces of evidence. This keeps a newsletter with forty tracking links from scoring like forty findings. The total is capped at 100.

Default verdicts: below 25 is `low_risk`, 25 to 54 is `suspicious`, 55 to 79 is `likely_phishing`, 80 and above is `high_confidence_phishing`. The score is a triage aid, not a probability. Check `signals` to see why a message scored the way it did.

Weights, thresholds, limits, brand domains, shorteners, TLDs, and risky extensions live in [`src/mail_sentry/default_rules.json`](src/mail_sentry/default_rules.json). A custom rules file only needs the values you want to change; `weights`, `thresholds`, and `limits` are merged key by key with the defaults:

```json
{
  "trusted_authserv_ids": ["mx.example.org"],
  "trusted_receivers": ["gw1.example.org", "gw2.example.org"],
  "weights": {"shortener": 4, "dmarc_fail": 22},
  "limits": {"max_archive_members": 100},
  "domain_hints": {
    "login.example.net": {"age_days": 5, "source": "internal inventory snapshot"}
  }
}
```

```powershell
mail-sentry message.eml --rules .\tenant-rules.json --pretty
```

`domain_hints` is data you supply. Mail Sentry does not look up registration age, and the report labels the value as a local hint.

## Authentication trust

Mail Sentry has two separate views of authentication. Neither one believes a header just because it is there.

### Local verification (`auth`)

* **DKIM** runs whenever a message carries `DKIM-Signature` headers and the `auth` extra is installed. Each signature (up to five) is verified against the raw `.eml` bytes. The public key comes from `--dns-records` or, with `--dns`, from live DNS. Without either, the result is `neutral` with a note, not a guess. A missing key record is `permerror`, a DNS timeout is `temperror`, a changed body or header is `fail`, and `verified` is true only for `pass`. Outlook `.msg` files do not keep the original bytes, so their signatures are reported as `neutral`.
* **SPF** is off until you pass `--check-spf`. The IP is the first untrusted hop: the `from` clause of the lowest `Received` header written by one of your `trusted_receivers`, the same boundary used for `Authentication-Results`. Without trusted receivers, the topmost `Received` header is used and the report says so. The MAIL FROM is the Return-Path, or `postmaster@` the HELO name when it is empty.
* **DMARC** passes when a passing DKIM signature's `d=` or a passing SPF domain aligns with the From domain (relaxed by default, strict when the policy says `adkim=s` or `aspf=s`). With DNS available the policy record is read for `p=`, `sp=`, and the alignment modes. A `fail` needs SPF to have been checked; otherwise the result is `neutral`, because an unchecked SPF could still have passed.

A snapshot for `--dns-records` maps host names to record types:

```json
{
  "sel1._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=MIIBIjANBg..."]},
  "example.com": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
  "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject"]}
}
```

### Gateway results (`message.authentication`)

Anyone can write an `Authentication-Results` header into a message before sending it. Mail Sentry ignores them all unless you tell it which gateway to trust, and then it still checks where the header sits:

1. The authserv-id must be in `trusted_authserv_ids`.
2. The header must be inside the block written by your gateway. That block ends at the first `Received` header added by a host outside `trusted_receivers` (which defaults to the authserv IDs), counting from the topmost trusted hop. Anything below that point arrived with the message.
3. Only the topmost header for each authserv-id is used.
4. Comments such as `(spf=fail)` are stripped before results are read.

Every header that was not used appears in `ignored_authentication_results` with a reason. This is a provenance check, not cryptographic validation. Your gateway should still strip inbound headers that claim its authserv-id.

## Lure dictionaries

Lure phrases live in [`src/mail_sentry/lures/`](src/mail_sentry/lures/), one JSON file per language: English, Arabic, French, Spanish, German, Portuguese, Russian, Chinese (Simplified), and Japanese. Each file lists terms or regular expressions with a weight from 1 to 5 under seven categories:

| Category | Rule |
| --- | --- |
| urgency | `urgency_language` |
| financial, invoice_payment | `payment_lure` |
| credential_reset | `credential_lure` |
| package_delivery | `delivery_lure` |
| prize_lottery | `prize_lure` |
| authority_impersonation | `authority_lure` |

A category fires when the distinct terms it matched add up to 2. Strong phrases ("votre mot de passe expire", "包裹被扣留") have weight 2 and fire alone. Common words ("facture", "Rechnung") have weight 1 and need a second hit, so an ordinary invoice notice stays quiet.

Text is normalized before matching: Unicode NFKC, case folded, accents folded for the Latin script languages (so "immediatement" still matches), Arabic diacritics and alef forms folded, and Russian yo read as ye.

The language comes from the body: langdetect when the `lang` extra is installed, otherwise a script count plus stopword check. `Content-Language` raises confidence when it agrees and is otherwise only reported, because the sender writes it. A confident detection on a message of 400 characters or more scans that language plus English. Short messages and weak detections scan every dictionary. English is always scanned.

## Samples

`samples/clean.eml`, `samples/suspicious.eml`, and `samples/phishing.eml` are an internal note, a delivery fee lure, and a credential harvester. With default rules they score 0 (`low_risk`), 43 (`suspicious`), and 100 (`high_confidence_phishing`). The authentication claims in the samples are not trusted by default, so they do not affect the scores. All sample domains use the reserved `.example` suffix.

## Tests

```powershell
python -m pip install -e ".[auth,archives,lang,msg]"
python -m unittest discover -s tests -v
```

Fixtures live in `tests/fixtures/`: DKIM signed and tampered messages with their key record, archives of every supported format (including a nested CAB, ZIP, 7z chain, compression bombs, and encrypted archives), and one lure message per language. `tests/fixtures/archives/build_fixtures.py` rebuilds the archives. SPF and DMARC tests answer DNS from an in-memory record set, so the suite never touches the network.

CI runs the suite on Ubuntu and Windows with Python 3.10 and 3.12 with every extra installed, plus one Ubuntu job with no extras to check that the core still runs and the dependent tests skip.

## Layout

```text
EML / MSG
   |
parsing.py              MIME parsing, MSG normalization, part limits, raw bytes
   |
header_analysis.py      sender identity, gateway result trust, Received chain
auth_verification.py    local DKIM, SPF, and DMARC
resolver.py             offline, snapshot, and live DNS answers
body_analysis.py        HTML parser, hidden content, active content
lure_language.py        language detection and lure dictionaries (lures/*.json)
url_analysis.py         normalization, IP forms, homoglyphs, wrappers
attachment_analysis.py  magic bytes, names, macros
archives.py             bounded scanning for every archive format
   |
scoring.py              per rule weights and verdict
   |
JSON report (cli.py)
```

## Limitations

* DKIM and DMARC need DNS answers. Offline runs without `--dns-records` report signatures as `neutral` and cannot decide DMARC.
* The SPF client IP is only as good as your gateway's `Received` header. Configure `trusted_receivers`; without it the topmost hop is used.
* ARC chains are not evaluated, so a forwarded message that broke DKIM on the way gets no credit for its earlier pass.
* URLs are never fetched. Decoded wrapper targets show what a link names, not where an HTTP request would end up. Shortener targets are unknown.
* The registrable domain logic uses a short list of common two label suffixes, not the full Public Suffix List.
* Lookalike detection compares against the brands in `trusted_domains` only. The confusable table covers common Latin, Cyrillic, and Greek lookalikes, not all of Unicode.
* CAB files using LZX or Quantum compression, and compressed RAR members without an extractor on the path, are listed but their contents are not read. ISO images are read through UDF, Joliet, Rock Ridge, or plain ISO 9660 names, in that order.
* Attached `message/rfc822` emails have their bodies and attachments analyzed, but their headers are not scored.
* Lure dictionaries cover nine languages and a few dozen phrases each. They catch common lures, not every wording, and languages outside the list fall back to a scan of all nine.
* `.msg` support relies on `extract-msg`. Embedded MSG attachments and unusual Outlook encodings may not convert fully.
* No rule set replaces sandboxing, a mail gateway, or analyst review. Tune the weights on your own benign mail before acting on scores.

## Safe handling

Run it on an isolated analysis host. Do not open extracted links or attachments on a production workstation. Mail Sentry reads the input file and writes the JSON report. It contacts DNS only when you ask it to, and nothing else.

## License

MIT. See [LICENSE](LICENSE).
