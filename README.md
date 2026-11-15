# Mail Sentry

Mail Sentry triages suspicious email for a SOC. Point it at an `.eml` or Outlook `.msg` file and it returns a JSON report: a score, a verdict, and every rule that fired with the evidence behind it.

It runs offline. It never opens URLs, resolves DNS names, queries reputation services, or executes attachments, so you can run it against live phishing samples on an isolated host.

## What it checks

**Headers**
* SPF, DKIM, and DMARC results, read only from your own gateway (see [Authentication trust](#authentication-trust))
* From, Return-Path, and Reply-To compared by organizational domain, so `mail.shop.example` and `bounces.shop.example` do not count as a mismatch
* Display names that carry a different address (`"ceo@brand.example" <x@other.example>`) or name a brand the sender address does not belong to
* Sender domains that imitate a brand (`micros0ft-login.example`)
* Duplicate or unparseable From headers, odd Received chains, and scripted X-Mailer values

**HTML and text**
* Password fields, with the form action they post to
* Scripts, any `on*` event handler, `javascript:` URLs, iframes, `srcdoc` documents (parsed too), and meta refresh redirects
* Hidden content that matters: large hidden text blocks, links inside hidden elements, zero width characters inside words, and bidirectional override characters. A short hidden preheader on its own is not flagged.
* Link text that shows one domain while the link goes to another
* Urgency and payment lure phrases in the subject and visible text. Hidden text is not used for these.

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
* ZIP and Office archives: every member name is checked, nested archives are opened up to a depth limit, encrypted members are reported by name, and text members are searched for URLs
* RAR5 archives with encrypted headers
* High entropy only for file types that are not compressed by design, so ordinary JPEG, PDF, and ZIP files do not trip it

## Install and run

Python 3.10 or later. The core uses only the standard library. MSG support needs `extract-msg`.

```powershell
python -m pip install -e ".[msg]"
mail-sentry samples/phishing.eml --pretty
mail-sentry message.msg --output report.json --pretty
```

Without the console script:

```powershell
python -m mail_sentry.cli samples/suspicious.eml --pretty
```

Exit codes: `0` when a report was written, `2` for input or configuration errors, `3` when a malformed message could not be analyzed.

## Example output

Abbreviated report for `samples/phishing.eml`:

```json
{
  "schema_version": "2.0",
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
  "urls": [
    {"url": "https://microsoft.com@198.51.100.25/secure", "host": "198.51.100.25",
     "flags": ["userinfo before hostname", "IP literal"], "wrapped_targets": []}
  ],
  "attachments": [],
  "parse_defects": {}
}
```

The full report also includes decoded headers, ignored Authentication-Results headers with the reason each was ignored, normalized URLs, archive member lists, and analysis notes.

## Scoring

Signals are grouped by rule. Each rule adds its weight once, no matter how many times it fired; the report still shows the count and up to five pieces of evidence. This keeps a newsletter with forty tracking links from scoring like forty findings. The total is capped at 100.

Default verdicts: below 25 is `low_risk`, 25 to 54 is `suspicious`, 55 to 79 is `likely_phishing`, 80 and above is `high_confidence_phishing`. The score is a triage aid, not a probability. Check `signals` to see why a message scored the way it did.

Weights, thresholds, limits, brand domains, shorteners, TLDs, and risky extensions live in [`src/mail_sentry/default_rules.json`](src/mail_sentry/default_rules.json). A custom rules file only needs the values you want to change; `weights`, `thresholds`, and `limits` are merged key by key with the defaults:

```json
{
  "trusted_authserv_ids": ["mx.example.org"],
  "trusted_receivers": ["gw1.example.org", "gw2.example.org"],
  "weights": {"shortener": 4},
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

Anyone can write an `Authentication-Results` header into a message before sending it. Mail Sentry ignores them all unless you tell it which gateway to trust, and then it still checks where the header sits:

1. The authserv-id must be in `trusted_authserv_ids`.
2. The header must be inside the block written by your gateway. That block ends at the first `Received` header added by a host outside `trusted_receivers` (which defaults to the authserv IDs), counting from the topmost trusted hop. Anything below that point arrived with the message.
3. Only the topmost header for each authserv-id is used.
4. Comments such as `(spf=fail)` are stripped before results are read.

Every header that was not used appears in `ignored_authentication_results` with a reason. This is a provenance check, not cryptographic validation. Your gateway should still strip inbound headers that claim its authserv-id.

## Samples

`samples/clean.eml`, `samples/suspicious.eml`, and `samples/phishing.eml` are an internal note, a delivery fee lure, and a credential harvester. With default rules they score 0 (`low_risk`), 35 (`suspicious`), and 100 (`high_confidence_phishing`). The authentication claims in the samples are not trusted by default, so they do not affect the scores. All sample domains use the reserved `.example` suffix.

## Tests

```powershell
python -m pip install -e ".[msg]"
python -m unittest discover -s tests -v
```

CI runs the suite on Ubuntu and Windows with Python 3.10 and 3.12.

## Layout

```text
EML / MSG
   |
parsing.py            MIME parsing, MSG normalization, part limits
   |
header_analysis.py    sender identity, authentication trust, Received chain
body_analysis.py      HTML parser, hidden content, active content, lure text
url_analysis.py       normalization, IP forms, homoglyphs, wrappers
attachment_analysis.py  magic bytes, names, macros, bounded archive scan
   |
scoring.py            per rule weights and verdict
   |
JSON report (cli.py)
```

## Limitations

* Authentication results are not validated cryptographically. The positional check depends on your gateway writing its own `Received` header and stripping forged results.
* URLs are never fetched. Decoded wrapper targets show what a link names, not where an HTTP request would end up. Shortener targets are unknown.
* The registrable domain logic uses a short list of common two label suffixes, not the full Public Suffix List.
* Lookalike detection compares against the brands in `trusted_domains` only. The confusable table covers common Latin, Cyrillic, and Greek lookalikes, not all of Unicode.
* Only ZIP based archives are opened. 7z, RAR (apart from RAR5 header encryption), CAB, ISO, and gzip are recorded but their contents are not inspected.
* Attached `message/rfc822` emails have their bodies and attachments analyzed, but their headers are not scored.
* Language rules are English only.
* `.msg` support relies on `extract-msg`. Embedded MSG attachments and unusual Outlook encodings may not convert fully.
* No rule set replaces sandboxing, a mail gateway, or analyst review. Tune the weights on your own benign mail before acting on scores.

## Safe handling

Run it on an isolated analysis host. Do not open extracted links or attachments on a production workstation. Mail Sentry reads the input file and writes the JSON report; it does nothing else.

## License

MIT. See [LICENSE](LICENSE).
