# MDR Alert Triage Bot

> **Python + Slack automation for IOC enrichment and EDR alert triage. Reduces manual triage time ~40% across 200+ daily alerts.**
> Drop-in for SOC analysts drowning in CrowdStrike / SentinelOne / Defender alerts.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Slack](https://img.shields.io/badge/notify-Slack-4A154B?logo=slack&logoColor=white)](#slack-output)
[![EDR](https://img.shields.io/badge/EDR-CrowdStrike%20%7C%20SentinelOne%20%7C%20Defender-1F4E79)](#supported-edrs)

---

## What it does

Reads a stream of EDR alerts (CrowdStrike Falcon, SentinelOne Singularity,
Microsoft Defender for Endpoint), normalizes them into a single canonical
shape, enriches every IOC against a local threat-intel database, and
classifies each alert into one of four actions:

| Action | Trigger |
|---|---|
| `block` | severity ∈ {critical, high} **AND** worst IOC score ≥ 90 |
| `escalate` | severity ∈ {critical, high} **AND** worst IOC score ≥ 70 |
| `investigate` | any alert with at least one IOC scoring ≥ 40 |
| `auto_close` | severity ≤ medium **AND** no enriched IOCs |

A Slack message summarizes the batch and shows the top-5 worst alerts as
colored attachments. The CLI exits non-zero (with `--fail-on-block`) when
anything reaches `block` so you can wire it into `kubectl exec` -style
auto-isolation playbooks.

```
======================================================================
  MDR Alert Triage Bot
======================================================================
[*] Alerts processed : 5
[*] By action        : {'block': 2, 'investigate': 1, 'auto_close': 2}
[*] By severity      : {'critical': 1, 'high': 1, 'medium': 1, 'low': 1, 'info': 1}
[*] Estimated time saved : ~10.0 min (~40% of 25 min manual triage)

[CRITICAL] BLOCK        powershell.exe
   vendor=crowdstrike  host=WIN-FIN-014  user=fin\jdoe
   tactic=Command and Control  technique=T1071.001
   worst IOC score: 98
     - 44d8...02f (sha256) score=98  [malware,loader,smokeloader]
     - 45.155.205.233 (ipv4) score=95  [c2,cobalt-strike,ransomware]
```

---

## Why you want this

- **Time savings are real.** Average manual triage is ~5 min/alert. At 200
  alerts/day that's 16+ analyst hours daily. Auto-closing the obvious noise
  and pre-enriching the rest cuts ~40% of that work.
- **Vendor-neutral.** CrowdStrike, SentinelOne, Defender all flow through
  the same canonical alert shape — your runbook doesn't change when the
  CISO swaps EDR.
- **Local intel first, OSINT optional.** Works offline / FedRAMP /
  air-gapped — the local threat-intel JSON is the source of truth. Public
  OSINT (abuse.ch, CISA KEV, etc.) plugs in via `--osint`.
- **Slack-native.** Posts a single threaded message per batch with colored
  attachments — your Tier-1 analysts don't need a new tool to learn.
- **Zero dependencies.** Python 3.8+ stdlib only.

---

## Quickstart

```bash
git clone https://github.com/CyberEnthusiastic/mdr-triage-bot.git
cd mdr-triage-bot

# Run against the bundled samples (5 alerts → 2 blocks):
python triage_bot.py --alerts samples/edr_alerts.json \
                     --intel samples/threat_intel.json

# Real run with Slack output:
python triage_bot.py --alerts /var/edr/alerts.json --intel ./intel/threat_intel.json \
                     --slack "$SLACK_WEBHOOK_URL" --json out.json

# Wire into CI / SOAR — non-zero on any 'block' decision:
python triage_bot.py --alerts alerts.json --intel intel.json --fail-on-block
```

---

## Supported EDRs

The vendor is auto-detected per alert — you can mix vendors in one feed.

| EDR | Detection signal | Severity mapping |
|---|---|---|
| **CrowdStrike Falcon** | `behaviors[]` + `device.hostname` | numeric 1-90 → critical/high/medium/low |
| **SentinelOne Singularity** | `threatInfo` + `agentRealtimeInfo` | "Critical/High/Medium/Low" → same |
| **Microsoft Defender for Endpoint** | `DeviceName` + `AlertId` | "High/Medium/Low/Informational" → bumped one tier (Defender's "High" = our "critical") |

Each alert is normalized into:

```json
{
  "alert_id": "...",
  "vendor": "crowdstrike",
  "severity": "critical",
  "ts": "2025-04-18T14:22:01Z",
  "host": "WIN-FIN-014",
  "user": "fin\\jdoe",
  "process": "powershell.exe",
  "iocs": ["sha256:...", "45.155.205.233"],
  "tactic": "Command and Control",
  "technique": "T1071.001",
  "raw": { ... }
}
```

Adding a new EDR = add a `_parse_<vendor>` function in `edr_parser.py`.

---

## IOC enrichment

Supported IOC types: `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`.

Threat-intel JSON shape (see `samples/threat_intel.json`):

```json
{
  "ipv4": {
    "45.155.205.233": {
      "score": 95,
      "tags": ["c2", "cobalt-strike", "ransomware"],
      "first_seen": "2024-09-12",
      "description": "Known Cobalt Strike C2 server."
    }
  },
  "domain": {"evil-update.click": {"score": 92, "tags": ["malware-distribution"]}},
  "sha256": {"44d8...": {"score": 98, "tags": ["malware", "smokeloader"]}}
}
```

You can populate this from CISA KEV, abuse.ch, MISP exports, or your own
hunting backlog. The enricher handles `dict-keyed-by-value` and
`list-of-objects` formats.

`--osint` (off by default) enables best-effort lookups against public,
no-auth OSINT feeds. Network errors degrade silently — never blocks a run.

---

## Slack output

Set the webhook URL via env var or flag:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../..."
python triage_bot.py --alerts alerts.json --intel intel.json
```

Each batch sends one Slack message:

- **Top-line summary**: total alerts, action breakdown
- **Top-5 worst attachments** with severity color, IOCs (max 5 per attachment), and remediation hint
- All formatted in mrkdwn so analysts can quote-reply / pivot quickly

---

## CLI

```
usage: triage_bot.py [-h] --alerts ALERTS [--intel INTEL] [--osint]
                     [--slack URL] [--json PATH] [--fail-on-block]
```

| Flag | Purpose |
|---|---|
| `--alerts PATH` | EDR alerts JSON (raw vendor format or canonical) |
| `--intel PATH` | Local threat-intel JSON |
| `--osint` | Enable best-effort public OSINT lookups |
| `--slack URL` | Slack incoming-webhook URL (env: `SLACK_WEBHOOK_URL`) |
| `--json PATH` | Write triage decisions JSON for downstream tools |
| `--fail-on-block` | Exit code 1 when any decision is `block` (CI gate) |

---

## Architecture

```
triage_bot.py     ── CLI, decision policy, console output
edr_parser.py     ── per-vendor parsers + canonical shape
ioc_enricher.py   ── classify_ioc, local + OSINT lookups
slack_notifier.py ── Slack incoming-webhook poster
samples/
  edr_alerts.json    ── 5-alert mixed-vendor fixture
  threat_intel.json  ── small but realistic IOC database
tests/
  test_bot.py     ── 11 unit tests, runs in <100ms
```

---

## Running the tests

```bash
python -m unittest discover tests
```

11 tests covering: IOC classification (7 cases), enrichment (known bad / known good / unknown), per-vendor EDR parsing, decision policy (block / escalate / investigate / auto_close), and end-to-end on the sample feed.

---

## License

MIT — see [LICENSE](./LICENSE).
