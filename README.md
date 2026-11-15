# Mail Sentry

Mail Sentry is a command line triage tool for `.eml` and Outlook `.msg` files. It extracts message metadata, inspects headers, HTML, links, and attachments, then produces a JSON report with a weighted score and the rules that contributed to it.

The analyzer is designed for offline handling of potentially hostile messages. It does not open URLs, perform DNS lookups, query reputation services, or execute attachments.

## Features

* SPF, DKIM, and DMARC results from configured trusted `Authentication-Results` servers, sender identity mismatches, unusual Received chains, and suspicious mailer strings
* Credential form, hidden content, active HTML, urgency, and payment lure checks
* Static URL extraction from HTML and plain text, with percent and HTML entity decoding, IDN and punycode checks, IP literal and URL userinfo checks, known shortener hints, and basic brand lookalike checks
* Attachment names, media types, sizes, SHA 256 hashes, byte entropy, risky extensions, deceptive double extensions, macro formats, encrypted ZIP indicators, and embedded URL strings in bounded document archive members
* Rule weights and verdict thresholds are configurable with JSON
* JSON output includes signal names, weights, explanations, and evidence snippets
* Optional MSG import with `extract-msg`
* Configurable limits for raw message size, MIME parts, attachment size, archive entries, expanded archive bytes, and nested redirect decoding

## Install and run

Python 3.10 or later is required. The base application uses only the standard library.

```powershell
py -m pip install -e .
mail-sentry samples/phishing.eml --pretty
```

Analyze an Outlook MSG file by installing the optional reader:

```powershell
py -m pip install -e ".[msg]"
mail-sentry message.msg --output report.json --pretty
```

Without installing the console command, run:

```powershell
py -m mail_sentry.cli samples/suspicious.eml --pretty
```

The command exits with code `0` when analysis completes and `2` for an input or configuration error. A successful analysis always emits one JSON document, including low risk messages.

## Example output

```json
{
  "schema_version": "1.1",
  "source_file": "phishing.eml",
  "verdict": "high_confidence_phishing",
  "score": 100,
  "signals": [
    {"rule": "auth_fail", "weight": 18, "detail": "A configured trusted authentication server reported a failed check"},
    {"rule": "credential_form", "weight": 28, "detail": "HTML message contains a form and password input"}
  ],
  "urls": [],
  "attachments": [],
  "summary": {"url_count": 0, "attachment_count": 0, "signal_count": 2, "explanation": ["..."]}
}
```

The sample is abbreviated. Actual output retains message header context and URL flags. The authentication failure signal is produced only when its `authserv-id` is configured as trusted.

## Scoring

Each triggered rule adds its configured weight. The total is capped at 100. Defaults classify scores below 25 as `low_risk`, 25 through 54 as `suspicious`, 55 through 79 as `likely_phishing`, and 80 or higher as `high_confidence_phishing`. Review the `signals` array for the evidence behind each score. A score is a triage aid, not a probability.

Rules are in [`src/mail_sentry/default_rules.json`](src/mail_sentry/default_rules.json). Copy the file and adjust `weights`, `thresholds`, limits, brand domains, URL shorteners, suspicious TLDs, and risky attachment extensions. To score SPF, DKIM, and DMARC failures, set `trusted_authserv_ids` to mail systems whose Authentication-Results headers your environment trusts. The receiving mail system must strip or replace inbound Authentication-Results headers that claim one of these trusted IDs before adding its own result. The local allowlist alone cannot establish header provenance. You can also provide organization maintained domain metadata:

```json
{
  "trusted_authserv_ids": ["mx.example.org"],
  "domain_hints": {
    "login.example.net": {"age_days": 5, "source": "internal inventory snapshot"}
  }
}
```

The age value is an operator supplied hint. Mail Sentry does not look up registration age itself. Run with the custom rules file using:

```powershell
mail-sentry message.eml --rules .\tenant-rules.json --pretty
```

Run the unit suite with:

```powershell
py -m pip install .
py -m unittest discover -s tests -v
```

## Sample set

`samples/clean.eml`, `samples/suspicious.eml`, and `samples/phishing.eml` provide an ordinary internal note, a delivery fee lure, and a credential harvesting message. With the default rules, the clean note scores 0 (`low_risk`), the delivery lure scores 43 (`suspicious`), and the credential harvester scores 100 (`high_confidence_phishing`). Authentication results are not trusted by default, so the sample failure claims do not affect these scores. The reports explain findings through sender mismatches, urgency and payment language, URL characteristics, and a password form. Analyze each with the CLI to inspect the complete explanations. The fixture domains use the reserved `.example` suffix and do not point to live services.

## Architecture

```text
EML / optional MSG
       |
 MIME parsing and attachment extraction
       |
 header | body and HTML | URL | attachment analyzers
       |
 weighted rules and threshold verdict
       |
 structured JSON report
```

The package separates orchestration from `parsing.py`, `header_analysis.py`, `body_analysis.py`, `url_analysis.py`, `attachment_analysis.py`, and `scoring.py`. `cli.py` handles command-line input and JSON output. The rules file holds tunable weights, trust settings, and resource limits. Message parsing uses Python's email package; MSG support normalizes common fields through `extract-msg`.

## Limitations

* SPF, DKIM, and DMARC values are read only from configured trusted authentication servers and are not cryptographically validated by this program. The receiving mail system must remove inbound headers that impersonate a trusted authserv ID; otherwise forged values may pass the configured-name check.
* URL destinations are never fetched. Common query based redirect wrappers are decoded offline into `redirect_destination` for inspection, but the actual final redirect destination is unknown. `domain_age` is populated only from local configuration hints. The tool deliberately avoids network access so analysts can inspect untrusted mail without contacting attacker infrastructure.
* IDN, brand lookalike, Received chain, and entropy checks are heuristics. Basic domain suffix handling is not a full public suffix database.
* Embedded URL extraction from arbitrary attachment bytes is opportunistic. Common Office XML and ZIP archives are inspected with bounded entry and expanded size limits. Encryption is detected for ZIP entries only. 7z, RAR, other formats, encrypted archives, nested archives, and malformed containers can hide content that static string inspection cannot recover.
* `.msg` compatibility depends on the optional third party parser and may vary for unusual Outlook encodings.
* No rule set can replace sandboxing, a mail gateway, or analyst review. Tune weights against the organization’s own benign traffic.

## Safe handling

Use an isolated analysis host and keep the analyzer offline when working with malicious samples. Do not open extracted links or attachments on a production workstation. Mail Sentry only reads the selected local file and writes the requested JSON report.

## License

MIT. See [LICENSE](LICENSE).
