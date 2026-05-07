"""
IOC enricher — looks up IPs, domains, and file hashes against:
  1. A local threat-intel JSON (immediate, deterministic — works offline)
  2. Optional public OSINT feeds (CISA KEV / abuse.ch / etc.) when reachable

The local DB is the source of truth in CI/airgapped runs. OSINT is a bonus
when network is available. The enricher always returns a result dict; missing
data degrades gracefully.

Reputation scoring is normalized to 0-100 (higher = more malicious):
  90+   confirmed bad — block
  70-89 high suspicion — escalate
  40-69 medium — collect more context
  0-39  unknown / low — close
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

_HASH_PATTERNS = {
    "md5": re.compile(r"^[a-f0-9]{32}$", re.I),
    "sha1": re.compile(r"^[a-f0-9]{40}$", re.I),
    "sha256": re.compile(r"^[a-f0-9]{64}$", re.I),
}

_DOMAIN_PATTERN = re.compile(
    r"^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I
)


def classify_ioc(value: str) -> str:
    """Return one of: ipv4, ipv6, domain, md5, sha1, sha256, url, unknown."""
    v = value.strip()
    if not v:
        return "unknown"
    if v.startswith(("http://", "https://")):
        return "url"
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    for kind, pat in _HASH_PATTERNS.items():
        if pat.match(v):
            return kind
    if _DOMAIN_PATTERN.match(v):
        return "domain"
    return "unknown"


@dataclass
class Enrichment:
    ioc: str
    kind: str
    score: int = 0  # 0-100
    sources: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: str = ""
    raw: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


class IOCEnricher:
    def __init__(self, intel_path: Optional[str] = None,
                 enable_osint: bool = False,
                 osint_timeout: float = 5.0):
        self.intel: dict = {}
        if intel_path and os.path.exists(intel_path):
            with open(intel_path, "r", encoding="utf-8") as fh:
                self.intel = json.load(fh)
        self.enable_osint = enable_osint
        self.osint_timeout = osint_timeout

    # ─── Local lookups ──────────────────────────────────────────────────────
    def _local_lookup(self, ioc: str, kind: str) -> dict:
        bucket = self.intel.get(kind) or self.intel.get(kind + "s") or {}
        if isinstance(bucket, dict):
            return bucket.get(ioc) or {}
        if isinstance(bucket, list):
            for entry in bucket:
                if isinstance(entry, dict) and entry.get("value") == ioc:
                    return entry
        return {}

    # ─── OSINT lookups (best-effort) ────────────────────────────────────────
    def _http_json(self, url: str) -> Optional[dict]:
        if not self.enable_osint:
            return None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mdr-triage-bot/1.0"})
            with urllib.request.urlopen(req, timeout=self.osint_timeout) as resp:
                if 200 <= resp.status < 300:
                    return json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, ValueError, TimeoutError):
            return None
        return None

    def _osint_ip(self, ip: str) -> dict:
        # Free, no-key tier of abuse.ch threatfox / urlhaus public API would
        # normally be hit here. Skipped in default offline build.
        return {}

    # ─── Public API ─────────────────────────────────────────────────────────
    def enrich(self, value: str) -> Enrichment:
        kind = classify_ioc(value)
        e = Enrichment(ioc=value, kind=kind)

        local = self._local_lookup(value, kind)
        if local:
            e.score = max(e.score, int(local.get("score", 0)))
            e.tags.extend(local.get("tags") or [])
            e.first_seen = local.get("first_seen") or e.first_seen
            e.last_seen = local.get("last_seen") or e.last_seen
            e.description = local.get("description") or e.description
            e.sources.append("local")
            e.raw["local"] = local

        if kind in ("ipv4", "ipv6") and self.enable_osint:
            osint = self._osint_ip(value)
            if osint:
                e.sources.append("osint")
                e.raw["osint"] = osint

        # Default scoring fallbacks for clearly suspicious patterns
        if e.score == 0 and kind in ("md5", "sha1", "sha256") and "malware" in e.tags:
            e.score = 90

        return e

    def enrich_many(self, values: list[str]) -> list[Enrichment]:
        return [self.enrich(v) for v in values]
