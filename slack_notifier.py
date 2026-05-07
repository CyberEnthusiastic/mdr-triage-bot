"""Slack incoming-webhook poster for triage notifications. Stdlib-only."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

_SEV_COLOR = {
    "critical": "#ff3b30",
    "high":     "#ff9500",
    "medium":   "#ffcc00",
    "low":      "#34d399",
    "info":     "#9ca3af",
}


def _attachment(alert: dict, score: int, action: str, top_iocs: list[dict]) -> dict:
    sev = alert.get("severity", "info")
    ioc_lines = "\n".join(
        f"• `{i['ioc']}` ({i['kind']}) — score {i['score']}" for i in top_iocs[:5]
    ) or "_(no IOCs)_"
    return {
        "color": _SEV_COLOR.get(sev, "#9ca3af"),
        "title": f"[{sev.upper()}] {alert.get('process') or alert.get('alert_id', '')}",
        "text": (f"*Action:* {action}   *Worst IOC score:* {score}\n"
                 f"*Vendor:* {alert.get('vendor', '?')}   "
                 f"*Host:* `{alert.get('host', '?')}`   "
                 f"*User:* `{alert.get('user', '?')}`\n"
                 f"*Tactic / Technique:* {alert.get('tactic', '?')} / {alert.get('technique', '?')}\n"
                 f"*IOCs:*\n{ioc_lines}"),
        "mrkdwn_in": ["text"],
    }


class SlackNotifier:
    def __init__(self, webhook_url: Optional[str] = None) -> None:
        self.webhook_url = (webhook_url or "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def _post(self, payload: dict) -> bool:
        if not self.enabled:
            return False
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.webhook_url, data=body,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return 200 <= r.status < 300
        except urllib.error.URLError:
            return False

    def post_triage(self, decisions: list[dict]) -> bool:
        if not decisions:
            return self._post({"text": ":white_check_mark: 0 alerts to triage."})
        from collections import Counter
        actions = Counter(d["action"] for d in decisions)
        text = (f":mag: *MDR triage — {len(decisions)} alerts*\n"
                f"BLOCK: *{actions.get('block', 0)}*  ·  "
                f"ESCALATE: {actions.get('escalate', 0)}  ·  "
                f"INVESTIGATE: {actions.get('investigate', 0)}  ·  "
                f"AUTO-CLOSE: {actions.get('auto_close', 0)}")
        # Show top-5 worst attachments only.
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        worst = sorted(
            decisions,
            key=lambda d: (rank.get(d["alert"]["severity"], 9), -d["worst_score"]),
        )[:5]
        atts = [_attachment(d["alert"], d["worst_score"], d["action"], d["enrichments"])
                for d in worst]
        return self._post({"text": text, "attachments": atts})
