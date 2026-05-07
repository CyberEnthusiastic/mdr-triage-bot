"""
EDR alert parser.

Normalizes alerts from CrowdStrike Falcon, SentinelOne Singularity, and
Microsoft Defender for Endpoint into a single canonical shape:

    {
      "alert_id": str,
      "vendor": "crowdstrike|sentinelone|defender",
      "severity": "critical|high|medium|low|info",
      "ts": "ISO-8601",
      "host": str,
      "user": str,
      "process": str,
      "iocs": [str, ...],
      "tactic": str,            # MITRE ATT&CK tactic, best-effort
      "technique": str,         # MITRE ATT&CK technique ID
      "raw": {...}
    }

A canonical alert is what the rest of the bot operates on — IOC enrichment,
Slack posting, and triage decisioning all accept this shape.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

_SEV_MAP = {
    # CrowdStrike severity scale 1-90
    "crowdstrike": lambda v: ("critical" if v >= 70 else "high" if v >= 50
                              else "medium" if v >= 30 else "low" if v >= 10 else "info"),
    # SentinelOne string severity
    "sentinelone": lambda v: {"Critical": "critical", "High": "high", "Medium": "medium",
                              "Low": "low"}.get(str(v), "info"),
    # Defender numeric / string severity
    "defender": lambda v: {"High": "critical", "Medium": "high",
                           "Low": "medium", "Informational": "info"}.get(str(v), "low"),
}


def _detect_vendor(raw: dict) -> str:
    if "device" in raw and "agent" in raw and "threatInfo" in raw:
        return "sentinelone"
    if "DeviceName" in raw and ("AlertId" in raw or "Severity" in raw):
        return "defender"
    if "behaviors" in raw or "DetectionId" in raw or "device" in raw and "hostname" in raw.get("device", {}):
        return "crowdstrike"
    return "unknown"


def _flatten_iocs(items: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for it in items or []:
        if isinstance(it, str):
            out.append(it.strip())
        elif isinstance(it, dict):
            for k in ("value", "ioc", "indicator", "hash", "ip", "domain", "url"):
                v = it.get(k)
                if isinstance(v, str):
                    out.append(v.strip())
    return [x for x in out if x]


def _parse_crowdstrike(raw: dict) -> dict:
    sev_raw = raw.get("max_severity") or raw.get("severity") or 0
    behaviors = raw.get("behaviors") or [{}]
    b0 = behaviors[0] if behaviors else {}
    iocs = []
    for b in behaviors:
        if b.get("md5"):
            iocs.append(b["md5"])
        if b.get("sha256"):
            iocs.append(b["sha256"])
        if b.get("ioc_value"):
            iocs.append(b["ioc_value"])
    return {
        "alert_id": raw.get("detection_id") or raw.get("DetectionId") or raw.get("id", ""),
        "vendor": "crowdstrike",
        "severity": _SEV_MAP["crowdstrike"](sev_raw if isinstance(sev_raw, int) else 0),
        "ts": raw.get("created_timestamp") or raw.get("first_behavior") or "",
        "host": raw.get("device", {}).get("hostname", "") or raw.get("hostname", ""),
        "user": b0.get("user_name") or raw.get("user_name", ""),
        "process": b0.get("filename") or "",
        "iocs": iocs,
        "tactic": b0.get("tactic", ""),
        "technique": b0.get("technique_id") or b0.get("technique", ""),
        "raw": raw,
    }


def _parse_sentinelone(raw: dict) -> dict:
    threat = raw.get("threatInfo", {}) or {}
    agent = raw.get("agentRealtimeInfo", {}) or raw.get("agent", {}) or {}
    iocs = []
    for k in ("sha256", "sha1", "md5"):
        v = threat.get(k)
        if v:
            iocs.append(v)
    return {
        "alert_id": threat.get("threatId") or raw.get("id", ""),
        "vendor": "sentinelone",
        "severity": _SEV_MAP["sentinelone"](threat.get("confidenceLevel") or threat.get("classificationSource", "")),
        "ts": threat.get("createdAt", ""),
        "host": agent.get("computerName") or agent.get("agentComputerName", ""),
        "user": threat.get("originatorProcess", "") or raw.get("user", ""),
        "process": threat.get("processName") or threat.get("filePath") or "",
        "iocs": iocs,
        "tactic": "",
        "technique": threat.get("mitigationStatus") or "",
        "raw": raw,
    }


def _parse_defender(raw: dict) -> dict:
    iocs = _flatten_iocs(raw.get("Evidence") or raw.get("evidence") or [])
    return {
        "alert_id": raw.get("AlertId") or raw.get("id", ""),
        "vendor": "defender",
        "severity": _SEV_MAP["defender"](raw.get("Severity") or raw.get("severity", "")),
        "ts": raw.get("AlertCreationTime") or raw.get("createdDateTime", ""),
        "host": raw.get("DeviceName") or raw.get("computerDnsName", ""),
        "user": raw.get("RelatedUser") or raw.get("userName", ""),
        "process": raw.get("Title", ""),
        "iocs": iocs,
        "tactic": raw.get("Category") or raw.get("Categories", ""),
        "technique": raw.get("MitreTechniques") or raw.get("attackTechniques", ""),
        "raw": raw,
    }


def parse_alert(raw: dict) -> dict:
    vendor = _detect_vendor(raw)
    if vendor == "crowdstrike":
        return _parse_crowdstrike(raw)
    if vendor == "sentinelone":
        return _parse_sentinelone(raw)
    if vendor == "defender":
        return _parse_defender(raw)
    # Fallback: treat raw as already-canonical or generic.
    return {
        "alert_id": raw.get("alert_id") or raw.get("id", ""),
        "vendor": "unknown",
        "severity": str(raw.get("severity", "info")).lower(),
        "ts": raw.get("ts", ""),
        "host": raw.get("host", ""),
        "user": raw.get("user", ""),
        "process": raw.get("process", ""),
        "iocs": list(raw.get("iocs") or []),
        "tactic": raw.get("tactic", ""),
        "technique": raw.get("technique", ""),
        "raw": raw,
    }


def parse_alert_file(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "alerts" in data:
        items = data["alerts"]
    elif isinstance(data, list):
        items = data
    else:
        items = [data]
    return [parse_alert(a) for a in items]
