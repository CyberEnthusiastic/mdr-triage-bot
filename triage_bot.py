#!/usr/bin/env python3
"""
MDR Alert Triage Bot — IOC enrichment + EDR alert triage with Slack output.

  $ python triage_bot.py --alerts samples/edr_alerts.json \
                         --intel samples/threat_intel.json
  $ python triage_bot.py --alerts alerts.json --intel intel.json \
                         --slack "$SLACK_WEBHOOK_URL" --json out.json

Decision policy:
  block         alert sev critical|high  AND  worst IOC score >= 90
  escalate     alert sev critical|high  AND  worst IOC score >= 70
  investigate  any other alert with at least one enriched IOC (score >= 40)
  auto_close   no IOC matches AND alert sev <= medium

Zero deps — Python 3.8+ stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter

# Force UTF-8 stdout where the host shell defaulted to cp1252 (Windows).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, ValueError):
    pass

from edr_parser import parse_alert_file
from ioc_enricher import IOCEnricher
from slack_notifier import SlackNotifier


_RESET = "\033[0m"
_COL = {
    "critical": "\033[1;91m", "high": "\033[1;33m",
    "medium":   "\033[1;36m", "low":  "\033[0;90m",
    "info":     "\033[0;90m", "DIM":  "\033[2m",
    "OK":       "\033[1;92m", "TITLE":"\033[1;94m",
}


def _c(key: str, s: str) -> str:
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return s
    return f"{_COL.get(key, '')}{s}{_RESET}"


# ─── Triage decisioning ─────────────────────────────────────────────────────
def decide(alert: dict, enrichments: list[dict]) -> tuple[str, int]:
    """Return (action, worst_ioc_score)."""
    worst = max((e["score"] for e in enrichments), default=0)
    sev = alert.get("severity", "info")
    if sev in ("critical", "high") and worst >= 90:
        return "block", worst
    if sev in ("critical", "high") and worst >= 70:
        return "escalate", worst
    if worst >= 40:
        return "investigate", worst
    if sev in ("low", "info"):
        return "auto_close", worst
    return "investigate", worst


# ─── Pipeline ───────────────────────────────────────────────────────────────
def triage(alerts_path: str, intel_path: str | None,
           enable_osint: bool = False) -> list[dict]:
    enricher = IOCEnricher(intel_path=intel_path, enable_osint=enable_osint)
    decisions: list[dict] = []
    for alert in parse_alert_file(alerts_path):
        enrichments = [e.as_dict() for e in enricher.enrich_many(alert.get("iocs") or [])]
        action, worst = decide(alert, enrichments)
        decisions.append({
            "alert": alert,
            "enrichments": enrichments,
            "worst_score": worst,
            "action": action,
        })
    return decisions


# ─── Output ─────────────────────────────────────────────────────────────────
def print_decisions(decisions: list[dict]) -> None:
    if not decisions:
        print(_c("OK", "[+] No alerts to triage."))
        return
    actions = Counter(d["action"] for d in decisions)
    sevs = Counter(d["alert"].get("severity") for d in decisions)
    print(_c("TITLE", "=" * 70))
    print(_c("TITLE", "  MDR Alert Triage Bot"))
    print(_c("TITLE", "=" * 70))
    print(f"[*] Alerts processed : {len(decisions)}")
    print(f"[*] By action        : {dict(actions)}")
    print(f"[*] By severity      : {dict(sevs)}")
    saved_min = round(len(decisions) * 0.4 * 5, 1)  # 5 min/alert avg, 40% reduction
    print(f"[*] Estimated time saved : ~{saved_min} min "
          f"(~40% of {len(decisions) * 5} min manual triage)\n")

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for d in sorted(decisions, key=lambda x: sev_rank.get(x["alert"].get("severity", "info"), 9)):
        a = d["alert"]
        sev = a.get("severity", "info")
        vendor = a.get("vendor", "?")
        host = a.get("host", "?")
        user = a.get("user", "?")
        tactic = a.get("tactic", "?")
        technique = a.get("technique", "?")
        worst = d["worst_score"]
        print(f"{_c(sev, '[' + sev.upper().ljust(8) + ']')} "
              f"{_c('TITLE', d['action'].upper().ljust(12))} "
              f"{a.get('process') or a.get('alert_id', '')}")
        print(f"   {_c('DIM', f'vendor={vendor}  host={host}  user={user}')}")
        print(f"   {_c('DIM', f'tactic={tactic}  technique={technique}')}")
        print(f"   {_c('DIM', f'worst IOC score: {worst}')}")
        for e in (d["enrichments"] or [])[:3]:
            tag = ",".join(e.get("tags") or []) or "no-tags"
            print(f"     - {e['ioc']:50} ({e['kind']:6}) score={e['score']:3}  [{tag}]")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Triage EDR alerts with IOC enrichment.")
    p.add_argument("--alerts", required=True, help="Path to EDR alerts JSON")
    p.add_argument("--intel", help="Path to local threat-intel JSON")
    p.add_argument("--osint", action="store_true",
                   help="Enable best-effort public OSINT lookups")
    p.add_argument("--slack", default=os.environ.get("SLACK_WEBHOOK_URL", ""),
                   help="Slack webhook URL (env: SLACK_WEBHOOK_URL)")
    p.add_argument("--json", help="Write decisions JSON to this path")
    p.add_argument("--fail-on-block", action="store_true",
                   help="Exit non-zero when any alert results in 'block'")
    args = p.parse_args(argv)

    decisions = triage(args.alerts, args.intel, enable_osint=args.osint)
    print_decisions(decisions)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"ts": int(time.time()), "decisions": decisions}, fh, indent=2)
        print(_c("DIM", f"   -> wrote {args.json}"))

    if args.slack:
        SlackNotifier(args.slack).post_triage(decisions)

    if args.fail_on_block and any(d["action"] == "block" for d in decisions):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
