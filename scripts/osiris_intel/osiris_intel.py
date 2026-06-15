#!/usr/bin/env python3
"""Thin read-only wrapper around the local OSIRIS sandbox and related public feeds.

Default target: http://127.0.0.1:3030.  Designed for Hermes/OpenClaw server use:
no wallet/trading/AIBTC writes, no public posting, no cron mutation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import html
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = os.environ.get("OSIRIS_BASE_URL", "http://127.0.0.1:3030")
CRYPTO_MARKET_KEYWORDS = {
    "crypto", "bitcoin", "btc", "ethereum", "eth", "stablecoin", "exchange", "binance", "coinbase",
    "okx", "bybit", "hyperliquid", "hype", "defi", "bridge", "wallet", "mining", "etf", "sec", "cftc",
    "sanction", "sanctions", "ofac", "aml", "tornado", "garantex", "mixer", "hack", "exploit",
    "ransomware", "cve", "kev", "withdrawal", "withdrawals", "bank", "capital controls",
}
CHOKEPOINT_KEYWORDS = {
    "hormuz", "red sea", "bab el mandeb", "suez", "panama canal", "taiwan", "persian gulf",
    "black sea", "strait", "canal", "port", "shipping", "oil", "brent", "wti", "lng", "pipeline",
}
HIGH_RISK_KEYWORDS = {
    "missile", "strike", "attack", "war", "riot", "unrest", "coup", "emergency", "nuclear", "drone",
    "bank run", "withdrawals paused", "halted withdrawals", "exploit", "zero-day", "critical",
}
GENERIC_PACKAGE_NAMES = {
    "file", "base-files", "coreutils", "findutils", "grep", "sed", "tar", "gzip", "make", "bash", "dash",
    "login", "passwd", "hostname", "mount", "less", "more", "time", "test",
}
PACKAGE_ALIASES = {
    "xz-utils": ["xz", "liblzma", "lzma"],
    "liblzma5": ["xz", "liblzma", "lzma"],
    "openssl": ["openssl", "libssl"],
    "openssh-client": ["openssh", "ssh"],
    "openssh-server": ["openssh", "sshd"],
    "nodejs": ["node.js", "nodejs", "node"],
}
CRYPTO_RISK_TERMS = {
    "tornado cash": {
        "label": "delisted-mixer-elevated-risk",
        "severity": "medium",
        "note": "Treasury delisted Tornado Cash in 2025, but it remains an elevated mixer/DPRK laundering-risk keyword. Do not treat a zero entity match as full clearance; verify current OFAC/OpenSanctions and address-level exposure before publishing or acting.",
    },
    "tornado": {
        "label": "crypto-mixer-risk",
        "severity": "low",
        "note": "Ambiguous term that can refer to Tornado Cash. Treat as a crypto-risk keyword only when crypto context corroborates it.",
    },
    "blender.io": {
        "label": "ofac-designated-mixer-risk",
        "severity": "high",
        "note": "OFAC-designated virtual currency mixer tied by Treasury to DPRK laundering and ransomware proceeds. Verify current OFAC/OpenSanctions and address-level data before clearing.",
    },
    "blender": {
        "label": "ofac-designated-mixer-risk",
        "severity": "medium",
        "note": "Ambiguous alias for Blender.io. Treat as sanctions risk when crypto/mixer context is present.",
    },
    "sinbad": {
        "label": "ofac-designated-mixer-risk",
        "severity": "high",
        "note": "Sinbad.io has been described by Treasury risk assessments as a DPRK-linked virtual asset mixer. Verify current OFAC/OpenSanctions and address-level data before clearing.",
    },
    "sinbad.io": {
        "label": "ofac-designated-mixer-risk",
        "severity": "high",
        "note": "Sinbad.io has been described by Treasury risk assessments as a DPRK-linked virtual asset mixer. Verify current OFAC/OpenSanctions and address-level data before clearing.",
    },
    "chipmixer": {
        "label": "mixer-enforcement-risk",
        "severity": "medium",
        "note": "Known mixer/enforcement-risk term. Verify current official sources and address-level exposure before clearing.",
    },
    "garantex": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "OFAC-designated exchange linked by Treasury to ransomware, Hydra, and sanctions evasion. Entity-name and address-level screening required.",
    },
    "grinex": {
        "label": "garantex-successor-sanctions-risk",
        "severity": "high",
        "note": "Treasury identified Grinex as a Garantex successor/sanctions-evasion vehicle. Entity-name and address-level screening required.",
    },
    "a7a5": {
        "label": "ruble-token-sanctions-evasion-risk",
        "severity": "high",
        "note": "Treasury linked the A7A5 ruble-backed token to Garantex/Grinex sanctions-evasion infrastructure. Treat as high-risk until cleared by current official sources.",
    },
    "a7 limited": {
        "label": "garantex-network-sanctions-risk",
        "severity": "high",
        "note": "Treasury linked A7 entities to Garantex/Grinex sanctions-evasion infrastructure. Screen entity and chain exposure.",
    },
    "old vector": {
        "label": "garantex-network-sanctions-risk",
        "severity": "high",
        "note": "Treasury linked Old Vector to A7A5/Garantex-related infrastructure. Screen entity and chain exposure.",
    },
    "suex": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "OFAC-designated virtual currency exchange associated by Treasury with illicit finance. Entity-name and address-level screening required.",
    },
    "chatex": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "OFAC-designated virtual currency exchange associated by Treasury with illicit finance. Entity-name and address-level screening required.",
    },
    "bitpapa": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "Treasury identified Bitpapa among sanctioned exchanges facilitating illicit activity. Screen current sanctions and address-level exposure.",
    },
    "netex24": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "Treasury identified NetEx24 among sanctioned exchanges facilitating illicit activity. Screen current sanctions and address-level exposure.",
    },
    "awex": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "Treasury identified AWEX among sanctioned exchanges facilitating illicit activity. Screen current sanctions and address-level exposure.",
    },
    "cryptex": {
        "label": "ofac-designated-exchange-risk",
        "severity": "high",
        "note": "OFAC-designated exchange linked by Treasury to ransomware and Russian cybercrime services. Screen entity and address-level exposure.",
    },
    "pm2btc": {
        "label": "fincen-primary-money-laundering-risk",
        "severity": "high",
        "note": "FinCEN identified PM2BTC as a Russian illicit finance/CVC-to-ruble exchange concern. Treat as high-risk and verify current sanctions/enforcement posture.",
    },
    "uaps": {
        "label": "payment-processor-cybercrime-risk",
        "severity": "high",
        "note": "Treasury linked UAPS/Ivanov infrastructure to ransomware, darknet markets, and fraud shops. Screen current official sources.",
    },
    "genesis market": {
        "label": "ofac-designated-darknet-market-risk",
        "severity": "high",
        "note": "OFAC-designated cybercrime/fraud marketplace term. Screen entity and exposure before acting.",
    },
    "hydra": {
        "label": "ofac-designated-darknet-market-risk",
        "severity": "medium",
        "note": "Ambiguous term. In crypto/darknet context, Hydra Market was OFAC-designated and tied to ransomware/illicit exchange flows.",
    },
    "hydra market": {
        "label": "ofac-designated-darknet-market-risk",
        "severity": "high",
        "note": "OFAC-designated darknet market tied by Treasury to ransomware and illicit exchange flows. Screen current official sources.",
    },
    "bitzlato": {
        "label": "crypto-exchange-enforcement-risk",
        "severity": "medium",
        "note": "Known crypto enforcement-risk term. Verify current sanctions, FinCEN/DOJ posture, and address-level exposure before clearing.",
    },
    "nobitex": {
        "label": "ofac-designated-iran-exchange-risk",
        "severity": "high",
        "note": "Treasury designated Nobitex in 2026 and linked it to Iranian sanctions evasion, IRGC-linked activity, and stablecoin flows. Screen current OFAC/OpenSanctions and address exposure.",
    },
    "wallex": {
        "label": "ofac-designated-iran-exchange-risk",
        "severity": "high",
        "note": "Treasury designated Wallex in 2026 as an Iranian digital asset exchange. Screen current OFAC/OpenSanctions and address exposure.",
    },
    "bitpin": {
        "label": "ofac-designated-iran-exchange-risk",
        "severity": "high",
        "note": "Treasury designated Bitpin in 2026 as an Iranian digital asset exchange. Screen current OFAC/OpenSanctions and address exposure.",
    },
    "ramzinex": {
        "label": "ofac-designated-iran-exchange-risk",
        "severity": "high",
        "note": "Treasury designated Ramzinex in 2026 as an Iranian digital asset exchange. Screen current OFAC/OpenSanctions and address exposure.",
    },
    "lazarus": {
        "label": "crypto-cyber-sanctions-risk",
        "severity": "high",
        "note": "Known DPRK cyber/sanctions-risk term. Entity-name sanctions lookup should also be checked.",
    },
    "lazarus group": {
        "label": "crypto-cyber-sanctions-risk",
        "severity": "high",
        "note": "Known DPRK cyber/sanctions-risk term. Entity-name sanctions lookup should also be checked.",
    },
    "kimsuky": {
        "label": "dprk-cyber-sanctions-risk",
        "severity": "high",
        "note": "Treasury-designated DPRK cyber espionage group term. Screen current OFAC/OpenSanctions before acting.",
    },
    "apt43": {
        "label": "dprk-cyber-sanctions-risk",
        "severity": "medium",
        "note": "Alias associated with Kimsuky/DPRK cyber activity. Treat as sanctions/cyber risk when context matches.",
    },
    "emerald sleet": {
        "label": "dprk-cyber-sanctions-risk",
        "severity": "medium",
        "note": "Alias associated with Kimsuky/DPRK cyber activity. Treat as sanctions/cyber risk when context matches.",
    },
    "tradertraitor": {
        "label": "dprk-crypto-cyber-risk",
        "severity": "high",
        "note": "DPRK crypto-targeting cyber campaign term. Screen current official sources and chain exposure.",
    },
    "conti": {
        "label": "ransomware-crypto-risk",
        "severity": "medium",
        "note": "Ransomware term linked by Treasury reporting to illicit crypto flows. Treat as market/security risk; verify entity-specific sanctions separately.",
    },
    "black basta": {
        "label": "ransomware-crypto-risk",
        "severity": "medium",
        "note": "Ransomware term linked by Treasury reporting to illicit crypto flows. Treat as market/security risk; verify entity-specific sanctions separately.",
    },
    "lockbit": {
        "label": "ransomware-sanctions-risk",
        "severity": "high",
        "note": "Treasury has designated LockBit-related actors. Treat as sanctions/cyber risk and verify current OFAC/OpenSanctions.",
    },
    "netwalker": {
        "label": "ransomware-crypto-risk",
        "severity": "medium",
        "note": "Ransomware term linked by Treasury reporting to illicit crypto flows. Treat as market/security risk; verify entity-specific sanctions separately.",
    },
    "ryuk": {
        "label": "ransomware-crypto-risk",
        "severity": "medium",
        "note": "Ransomware term linked by Treasury reporting to illicit crypto flows. Treat as market/security risk; verify entity-specific sanctions separately.",
    },
    "trickbot": {
        "label": "ransomware-cyber-sanctions-risk",
        "severity": "high",
        "note": "Treasury/OFAC has targeted Trickbot-linked actors. Treat as sanctions/cyber risk and verify current OFAC/OpenSanctions.",
    },
    "sodinokibi": {
        "label": "ransomware-crypto-risk",
        "severity": "medium",
        "note": "Ransomware term linked by Treasury reporting to illicit crypto flows. Treat as market/security risk; verify entity-specific sanctions separately.",
    },
    "gandcrab": {
        "label": "ransomware-crypto-risk",
        "severity": "medium",
        "note": "Ransomware term linked by Treasury reporting to illicit crypto flows. Treat as market/security risk; verify entity-specific sanctions separately.",
    },
    "mixer": {
        "label": "generic-mixer-risk",
        "severity": "medium",
        "note": "Generic mixer keyword. Not an entity match; use as a cue for address-level and official-source screening.",
    },
    "tumbler": {
        "label": "generic-mixer-risk",
        "severity": "medium",
        "note": "Generic tumbler keyword. Not an entity match; use as a cue for address-level and official-source screening.",
    },
    "no kyc": {
        "label": "no-kyc-exchange-risk",
        "severity": "medium",
        "note": "Generic no-KYC exchange keyword. Not a sanctions match; use as a cue for enhanced due diligence.",
    },
    "sanctions evasion": {
        "label": "generic-sanctions-evasion-risk",
        "severity": "high",
        "note": "Generic sanctions-evasion keyword. Requires official-source and address/entity-level verification.",
    },
    "ruble-backed": {
        "label": "ruble-token-sanctions-evasion-risk",
        "severity": "medium",
        "note": "Generic ruble-backed token risk cue; check A7A5/Garantex/Grinex context and current official sources.",
    },
}
CRYPTO_ADDRESS_PATTERNS = [
    ("eth-address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("btc-address", re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", re.IGNORECASE)),
    ("tron-address", re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")),
]
EVM_CHAINS = {
    "ethereum": {
        "chain_id": "1",
        "native": "ETH",
        "rpc": "https://ethereum.publicnode.com",
        "explorer": "https://etherscan.io/address/{address}",
    },
    "base": {
        "chain_id": "8453",
        "native": "ETH",
        "rpc": "https://base-rpc.publicnode.com",
        "explorer": "https://basescan.org/address/{address}",
    },
    "arbitrum": {
        "chain_id": "42161",
        "native": "ETH",
        "rpc": "https://arbitrum-one-rpc.publicnode.com",
        "explorer": "https://arbiscan.io/address/{address}",
    },
    "optimism": {
        "chain_id": "10",
        "native": "ETH",
        "rpc": "https://optimism-rpc.publicnode.com",
        "explorer": "https://optimistic.etherscan.io/address/{address}",
    },
    "polygon": {
        "chain_id": "137",
        "native": "POL",
        "rpc": "https://polygon-bor-rpc.publicnode.com",
        "explorer": "https://polygonscan.com/address/{address}",
    },
    "bsc": {
        "chain_id": "56",
        "native": "BNB",
        "rpc": "https://bsc-rpc.publicnode.com",
        "explorer": "https://bscscan.com/address/{address}",
    },
}
NON_EVM_EXPLORERS = {
    "btc-address": "https://mempool.space/address/{address}",
    "tron-address": "https://tronscan.org/#/address/{address}",
}
MSTR_CIK = "0001050446"
MSTR_SEC_UA = os.environ.get("MSTR_SEC_USER_AGENT", "OpalGorillaRisk/1.0 admin@example.com")
MSTR_BASELINE_SALE_HOLDINGS = 843_706
MSTR_BASELINE_PRESS_HOLDINGS = 843_738
MSTR_BASELINE_DATE = "2026-06-01"


class HttpJsonError(Exception):
    def __init__(self, status: int, url: str, payload: Any):
        self.status = status
        self.url = url
        self.payload = payload
        super().__init__(self._message())

    def _message(self) -> str:
        if isinstance(self.payload, dict):
            return str(self.payload.get("error") or self.payload.get("message") or self.payload)
        return str(self.payload)


def http_json(url: str, timeout: float = 15.0) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Hermes-OSIRIS-Intel/1.0"})
    parsed = urllib.parse.urlparse(url)
    is_local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    attempts = 3 if is_local else 1
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            if is_local:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                resp_ctx = opener.open(req, timeout=timeout)  # noqa: S310 - local OSIRIS only
            else:
                resp_ctx = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - controlled/public URLs only
            with resp_ctx as resp:
                data = resp.read()
            return json.loads(data.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                payload: Any = json.loads(body)
            except json.JSONDecodeError:
                payload = {"error": body.strip() or exc.reason}
            raise HttpJsonError(exc.code, url, payload) from exc
        except urllib.error.URLError as exc:
            last_error = exc
            if not is_local or attempt == attempts - 1:
                break
            time.sleep(0.25 * (attempt + 1))
    if last_error:
        raise last_error
    raise RuntimeError(f"Request failed without error: {url}")


def http_json_post(url: str, payload: dict[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "Hermes-OSIRIS-Intel/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - controlled/public URLs only
        return json.loads(resp.read().decode("utf-8"))


def http_text(url: str, timeout: float = 15.0, user_agent: str = "Hermes-OSIRIS-Intel/1.0") -> str:
    req = urllib.request.Request(url, headers={"Accept": "text/html,application/xhtml+xml,text/plain,*/*", "User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - controlled/public URLs only
        return resp.read().decode("utf-8", errors="replace")


def local_api(base_url: str, path: str, params: dict[str, str] | None = None, timeout: float = 15.0) -> dict[str, Any]:
    base = base_url.rstrip("/")
    qs = ""
    if params:
        qs = "?" + urllib.parse.urlencode(params)
    return http_json(f"{base}{path}{qs}", timeout=timeout)


def text_blob(item: dict[str, Any]) -> str:
    fields = ["name", "title", "description", "type", "source", "vendor", "product"]
    return " ".join(str(item.get(f, "")) for f in fields).lower()


def rank_events(events: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for event in events:
        blob = text_blob(event)
        matched: list[str] = []
        score = 0
        for kw in sorted(CRYPTO_MARKET_KEYWORDS | CHOKEPOINT_KEYWORDS | HIGH_RISK_KEYWORDS):
            if kw in blob:
                matched.append(kw)
                if kw in CRYPTO_MARKET_KEYWORDS:
                    score += 3
                if kw in CHOKEPOINT_KEYWORDS:
                    score += 4
                if kw in HIGH_RISK_KEYWORDS:
                    score += 5
        try:
            score += min(int(event.get("count", 0)), 5)
        except (TypeError, ValueError):
            pass
        if event.get("type") in {"conflict", "unrest"}:
            score += 2
        copy = dict(event)
        copy["score"] = score
        copy["matched_keywords"] = matched[:12]
        ranked.append(copy)
    return sorted(ranked, key=lambda e: (e.get("score", 0), e.get("count", 0)), reverse=True)[:limit]


def is_recent_news_item(item: dict[str, Any], max_age_hours: int = 72) -> bool:
    published = str(item.get("published") or item.get("published_date") or "").strip()
    if not published:
        return True
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return True
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds() / 3600
    return age_hours <= max_age_hours


def rank_news(news: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for item in news:
        if not is_recent_news_item(item):
            continue
        blob = text_blob(item)
        matched = [kw for kw in sorted(CRYPTO_MARKET_KEYWORDS | CHOKEPOINT_KEYWORDS | HIGH_RISK_KEYWORDS) if kw in blob]
        try:
            risk = int(item.get("risk_score", 0) or 0)
        except (TypeError, ValueError):
            risk = 0
        score = risk + len(matched) * 2
        copy = dict(item)
        copy["score"] = score
        copy["matched_keywords"] = matched[:12]
        enriched.append(copy)
    return sorted(enriched, key=lambda n: n.get("score", 0), reverse=True)[:limit]


def fetch_cisa_kev(days: int = 30, limit: int = 15) -> list[dict[str, Any]]:
    data = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20)
    now = time.time()
    out: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", []):
        date_added = v.get("dateAdded") or ""
        try:
            added_ts = time.mktime(time.strptime(date_added, "%Y-%m-%d"))
            age_days = (now - added_ts) / 86400
        except ValueError:
            age_days = 9999
        if age_days <= days:
            out.append({
                "id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "date": date_added,
                "due": v.get("dueDate"),
                "known_ransomware": v.get("knownRansomwareCampaignUse"),
                "source": "CISA KEV",
            })
    return out[:limit]


def sec_archive_url(accession: str, primary_document: str) -> str:
    acc_no_dash = accession.replace("-", "")
    return f"https://www.sec.gov/Archives/edgar/data/{int(MSTR_CIK)}/{acc_no_dash}/{primary_document}"


def sec_recent_mstr_8ks(limit: int = 8) -> list[dict[str, Any]]:
    data = http_json(f"https://data.sec.gov/submissions/CIK{MSTR_CIK}.json", timeout=20)
    recent = ((data.get("filings") or {}).get("recent") or {})
    rows: list[dict[str, Any]] = []
    for acc, form, filing_date, doc, desc in zip(
        recent.get("accessionNumber", []),
        recent.get("form", []),
        recent.get("filingDate", []),
        recent.get("primaryDocument", []),
        recent.get("primaryDocDescription", []),
    ):
        if form != "8-K":
            continue
        url = sec_archive_url(str(acc), str(doc))
        rows.append({"accession": acc, "form": form, "filing_date": filing_date, "primary_document": doc, "description": desc, "url": url})
        if len(rows) >= limit:
            break
    return rows


def html_to_text(raw: str) -> str:
    text = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _snippet(text: str, start: int, end: int, radius: int = 130) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].strip()


def _btc_int(value: str) -> int:
    clean = re.sub(r"[^\d.,]", "", value).replace(",", "")
    if "." in clean:
        return int(float(clean))
    return int(clean)


def extract_mstr_btc_facts(text: str) -> dict[str, list[dict[str, Any]]]:
    plain = html_to_text(text)
    facts: dict[str, list[dict[str, Any]]] = {"holdings": [], "acquired": [], "sold": []}
    for match in re.finditer(
        r"\bBTC\s+Acquired\b.{0,420}?\bAggregate\s+BTC\s+Holdings\b.{0,260}?\b([0-9][0-9,.]{0,})\s+\$\s+[0-9][0-9,.]*\s+\$\s+[0-9][0-9,.]*\s+([0-9][0-9,]{2,})\s+\$",
        plain,
        flags=re.IGNORECASE,
    ):
        try:
            acquired = _btc_int(match.group(1))
            holdings = _btc_int(match.group(2))
        except (IndexError, ValueError):
            continue
        facts["acquired"].append({"amount": acquired, "snippet": _snippet(plain, match.start(1), match.end(1))})
        facts["holdings"].append({"amount": holdings, "snippet": _snippet(plain, match.start(2), match.end(2))})
    patterns = {
        "holdings": [
            r"\b(?:holds?|held|hodl|hodls|holdings(?:\s+of)?|now\s+holds?)\s+(?:approximately\s+|about\s+|more\s+than\s+)?([0-9][0-9,]{2,})\s+(?:bitcoin|BTC)\b",
            r"\b([0-9][0-9,]{2,})\s+(?:bitcoin|BTC)\s+(?:on\s+its\s+balance\s+sheet|at\s+month-end|as\s+of|held)\b",
            r"\bAggregate\s+BTC\s+Holdings\b.{0,220}?\b([0-9][0-9,]{2,})\b",
        ],
        "acquired": [
            r"\b(?:acquired|purchased|purchase|to\s+purchase|used\s+[^.]{0,120}?\s+to\s+purchase)\s+(?:approximately\s+|about\s+|an\s+additional\s+)?([0-9][0-9,]{0,})\s+(?:bitcoin|BTC)\b",
        ],
        "sold": [
            r"\b(?:sold|sale\s+of|disposal\s+of)\s+(?:approximately\s+|about\s+|some\s+of\s+its\s+holdings\s+for\s+)?([0-9][0-9,.]{0,})\s+(?:bitcoin|BTC)\b",
            r"\bBTC\s+Sold\b.{0,220}?\bAverage\s+Sale\s+Price(?:\s*\([^)]+\))?\s+([0-9][0-9,.]{0,})\s*(?:\([^)]+\))?\s+\$",
        ],
    }
    for kind, regs in patterns.items():
        seen: set[tuple[int, str]] = set()
        for reg in regs:
            for match in re.finditer(reg, plain, flags=re.IGNORECASE):
                try:
                    amount = _btc_int(match.group(1))
                except (IndexError, ValueError):
                    continue
                if amount <= 0:
                    continue
                if kind == "holdings" and amount < 100_000:
                    continue
                key = (amount, match.group(0).lower()[:40])
                if key in seen:
                    continue
                seen.add(key)
                facts[kind].append({"amount": amount, "snippet": _snippet(plain, match.start(), match.end())})
    return facts


def fetch_mstr_hint_articles(limit: int = 5) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    query = '"Michael Saylor" "add more dots"'
    params = {
        "query": query,
        "mode": "ArtList",
        "format": "json",
        "timespan": "7d",
        "maxrecords": str(limit),
        "sort": "datedesc",
    }
    url = "https://api.gdeltproject.org/api/v2/doc/doc?" + urllib.parse.urlencode(params)
    try:
        data = http_json(url, timeout=18)
    except Exception as exc:  # noqa: BLE001
        return [], [str(exc)]
    out: list[dict[str, Any]] = []
    for item in data.get("articles", [])[:limit]:
        blob = " ".join(str(item.get(k, "")) for k in ("title", "seendate", "domain", "url")).lower()
        if "saylor" in blob or "strategy" in blob or "mstr" in blob:
            out.append({
                "title": item.get("title"),
                "url": item.get("url"),
                "domain": item.get("domain"),
                "seendate": item.get("seendate"),
                "source": "GDELT DOC hint search",
            })
    return out, errors


def analyze_mstr_watch(
    filings: list[dict[str, Any]],
    hints: list[dict[str, Any]] | None = None,
    errors: list[str] | None = None,
    baseline_date: str = MSTR_BASELINE_DATE,
    baseline_sale_holdings: int = MSTR_BASELINE_SALE_HOLDINGS,
    baseline_press_holdings: int = MSTR_BASELINE_PRESS_HOLDINGS,
) -> dict[str, Any]:
    hints = hints or []
    errors = errors or []
    normalized: list[dict[str, Any]] = []
    for filing in filings:
        text = str(filing.get("text") or "")
        facts = filing.get("facts") if isinstance(filing.get("facts"), dict) else extract_mstr_btc_facts(text)
        normalized.append({**filing, "facts": facts})

    latest_holding: dict[str, Any] | None = None
    buy_events: list[dict[str, Any]] = []
    sale_events: list[dict[str, Any]] = []
    for filing in normalized:
        date = str(filing.get("filing_date") or "")
        url = filing.get("url")
        acc = filing.get("accession")
        for row in (filing.get("facts") or {}).get("holdings", []):
            event = {**row, "filing_date": date, "url": url, "accession": acc}
            if latest_holding is None or date >= str(latest_holding.get("filing_date") or ""):
                latest_holding = event
        for row in (filing.get("facts") or {}).get("acquired", []):
            buy_events.append({**row, "filing_date": date, "url": url, "accession": acc})
        for row in (filing.get("facts") or {}).get("sold", []):
            sale_events.append({**row, "filing_date": date, "url": url, "accession": acc})

    fresh_buys = [e for e in buy_events if str(e.get("filing_date") or "") >= baseline_date]
    fresh_sales = [e for e in sale_events if str(e.get("filing_date") or "") >= baseline_date]
    hint_present = bool(hints)

    status = "no_fresh_filing"
    confidence = "medium"
    verdict = "No fresh confirmed Strategy bitcoin acquisition found."
    latest_amount = int(latest_holding.get("amount")) if latest_holding else None

    if fresh_buys and (latest_amount is None or latest_amount > baseline_sale_holdings):
        status = "confirmed_buy"
        confidence = "high"
        verdict = "Confirmed buy/update found in fresh Strategy filing text."
    elif hint_present:
        status = "hint_only"
        confidence = "medium"
        verdict = "Saylor/Strategy buy hint found, but no fresh confirming 8-K/press acquisition in checked filings."
    elif fresh_sales:
        status = "sale_update"
        confidence = "high"
        verdict = "Fresh filing text contains bitcoin sale/update, not a confirmed new buy."
    elif errors and not normalized:
        status = "degraded"
        confidence = "low"
        verdict = "Primary source checks degraded; cannot confirm no fresh filing."

    return {
        "status": status,
        "confidence": confidence,
        "verdict": verdict,
        "baseline": {
            "since": baseline_date,
            "post_sale_holdings_btc": baseline_sale_holdings,
            "press_holdings_btc": baseline_press_holdings,
        },
        "latest_holding": latest_holding,
        "buy_events": sorted(buy_events, key=lambda x: str(x.get("filing_date") or ""), reverse=True)[:5],
        "sale_events": sorted(sale_events, key=lambda x: str(x.get("filing_date") or ""), reverse=True)[:5],
        "hints": hints[:5],
        "filings_checked": [
            {k: f.get(k) for k in ("filing_date", "accession", "primary_document", "url")}
            for f in normalized[:8]
        ],
        "errors": errors,
        "caveat": "Do not call a Saylor purchase confirmed until Strategy press/SEC 8-K text confirms acquired/purchased BTC or higher holdings.",
    }


def collect_mstr_watch(limit: int = 6) -> dict[str, Any]:
    errors: list[str] = []
    filings: list[dict[str, Any]] = []
    try:
        rows = sec_recent_mstr_8ks(limit=limit)
        for row in rows:
            copy = dict(row)
            try:
                copy["text"] = http_text(str(row["url"]), timeout=20, user_agent=MSTR_SEC_UA)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"SEC filing fetch failed {row.get('accession')}: {exc}")
                copy["text"] = ""
            filings.append(copy)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"SEC submissions failed: {exc}")
    hints, hint_errors = fetch_mstr_hint_articles(limit=5)
    errors.extend(f"GDELT hint search: {err}" for err in hint_errors)
    result = analyze_mstr_watch(filings, hints=hints, errors=errors)
    result["sources"] = {
        "primary": "SEC data.sec.gov submissions + SEC Archives 8-K documents",
        "hint": "GDELT DOC search for Saylor add-more-dots coverage",
        "strategy_press": "Strategy website may be unavailable from this host; SEC is treated as primary.",
    }
    return result


def collect_radar(base_url: str = DEFAULT_BASE_URL, limit: int = 8) -> dict[str, Any]:
    payload: dict[str, Any] = {"base_url": base_url, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        health = local_api(base_url, "/api/health", timeout=8)
        payload["health"] = {"ok": health.get("status") == "operational", "status": health.get("status"), "raw": health}
    except Exception as exc:  # noqa: BLE001 - report full integration error
        payload["health"] = {"ok": False, "error": str(exc)}

    try:
        gdelt = local_api(base_url, "/api/gdelt", timeout=25)
        gdelt_events = gdelt.get("events", [])
        payload["gdelt_meta"] = {
            "total": gdelt.get("total", len(gdelt_events) if isinstance(gdelt_events, list) else 0),
            "source": gdelt.get("source"),
            "errors": gdelt.get("errors") or [],
            "partial": bool(gdelt.get("partial")),
            "fallback": bool(gdelt.get("fallback")),
            "stale": bool(gdelt.get("stale")),
            "source_mode": gdelt.get("source_mode"),
            "upstream_status": gdelt.get("upstream_status") or {},
            "rate_limit_hits": int(gdelt.get("rate_limit_hits") or 0),
            "timeout_hits": int(gdelt.get("timeout_hits") or 0),
            "circuit_open_until": gdelt.get("circuit_open_until"),
        }
        payload["gdelt"] = rank_events(gdelt.get("events", []), limit=limit)
    except Exception as exc:  # noqa: BLE001
        payload["gdelt_error"] = str(exc)
        payload["gdelt_meta"] = {"total": 0, "source": None, "errors": [str(exc)]}
        payload["gdelt"] = []

    try:
        news = local_api(base_url, "/api/news", timeout=25)
        payload["news"] = rank_news(news.get("news", []), limit=limit)
    except Exception as exc:  # noqa: BLE001
        payload["news_error"] = str(exc)
        payload["news"] = []

    try:
        payload["kev"] = fetch_cisa_kev(days=30, limit=limit)
    except Exception as exc:  # noqa: BLE001
        payload["kev_error"] = str(exc)
        payload["kev"] = []
    return payload


def _line(label: str, value: Any) -> str:
    return f"- {label}: {value}"


def _clip(value: Any, limit: int = 110) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _quality_label(gdelt_meta: dict[str, Any]) -> str:
    total = int(gdelt_meta.get("total") or 0)
    if total <= 0:
        return "GDELT DEGRADED"
    if gdelt_meta.get("stale"):
        return "GDELT STALE"
    if gdelt_meta.get("partial") or gdelt_meta.get("errors") or gdelt_meta.get("fallback"):
        return "GDELT PARTIAL"
    return "GDELT OK"


def _upstream_summary(status: dict[str, Any]) -> str:
    if not status:
        return "нет детализации"
    counts: dict[str, int] = {}
    for value in status.values():
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    order = ["ok", "rate_limited", "timeout", "error", "skipped_circuit", "skipped"]
    chunks = [f"{key}={counts[key]}" for key in order if counts.get(key)]
    for key in sorted(set(counts) - set(order)):
        chunks.append(f"{key}={counts[key]}")
    return ", ".join(chunks) if chunks else "нет детализации"


def _best_signal(payload: dict[str, Any]) -> dict[str, Any] | None:
    gdelt = payload.get("gdelt") or []
    news = payload.get("news") or []
    if gdelt:
        return {"source": "GDELT", **gdelt[0]}
    if news:
        return {"source": "Telegram/RSS", "name": news[0].get("title"), "score": news[0].get("score", news[0].get("risk_score", 0)), "url": news[0].get("link"), **news[0]}
    kev = payload.get("kev") or []
    if kev:
        return {"source": "CISA KEV", "name": kev[0].get("id"), "score": 0, **kev[0]}
    return None


def _signal_line(prefix: str, item: dict[str, Any]) -> str:
    title = _clip(item.get("name") or item.get("title") or item.get("id") or "untitled", 95)
    score = item.get("score", item.get("risk_score", 0))
    category = item.get("type") or item.get("source") or item.get("vendor") or "event"
    url = item.get("url") or item.get("link") or ""
    return f"- [{prefix}] score {score} | {category} | {title} | {_clip(url, 90)}".rstrip()


def crypto_risk_warnings(query: str) -> list[dict[str, str]]:
    normalized = re.sub(r"[^\w.\s-]+", " ", query.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    warnings: list[dict[str, str]] = []
    if any(pattern.search(query) for _, pattern in CRYPTO_ADDRESS_PATTERNS):
        warnings.append({
            "term": "crypto-address",
            "label": "address-screening-required",
            "severity": "info",
            "note": "Input looks like a cryptocurrency address. Entity-name lookup is insufficient; screen OFAC/OpenSanctions wallet data and chain exposure before clearing.",
            "source": "local crypto-risk address detector",
        })
    for term, meta in sorted(CRYPTO_RISK_TERMS.items(), key=lambda item: len(item[0]), reverse=True):
        if term in normalized:
            if any(term in existing["term"] for existing in warnings):
                continue
            if term in {"mixer", "tumbler"} and any("mixer" in existing["label"] for existing in warnings):
                continue
            warnings.append({
                "term": term,
                "label": meta["label"],
                "severity": meta["severity"],
                "note": meta["note"],
                "source": "local crypto-risk keyword layer",
            })
    return warnings


def enrich_sanctions_result(result: dict[str, Any], query: str) -> dict[str, Any]:
    enriched = dict(result)
    warnings = crypto_risk_warnings(query)
    enriched["crypto_risk"] = {
        "warnings": warnings,
        "needs_address_level_check": bool(warnings),
        "caveat": (
            "Entity-name sanctions lookup is not address-level blockchain screening. "
            "For mixers, bridges, malware clusters, and wallets, treat zero matches as inconclusive."
        ),
    }
    return enriched


def detect_address_kind(value: str) -> dict[str, Any]:
    query = value.strip()
    for kind, pattern in CRYPTO_ADDRESS_PATTERNS:
        match = pattern.search(query)
        if match:
            address = match.group(0)
            family = "evm" if kind == "eth-address" else kind.removesuffix("-address")
            return {"ok": True, "kind": kind, "family": family, "address": address, "normalized": address.lower() if family == "evm" else address}
    return {"ok": False, "kind": "unknown", "family": "unknown", "address": query, "normalized": query}


def wei_to_native(hex_value: str) -> float:
    try:
        return int(hex_value, 16) / 10**18
    except (TypeError, ValueError):
        return 0.0


def evm_rpc(chain: dict[str, str], method: str, params: list[Any], timeout: float = 10.0) -> Any:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    data = http_json_post(chain["rpc"], payload, timeout=timeout)
    if "error" in data:
        raise RuntimeError(str(data["error"].get("message") or data["error"]))
    return data.get("result")


def decode_abi_string(hex_data: str) -> str | None:
    if not hex_data or not hex_data.startswith("0x"):
        return None
    raw = hex_data[2:]
    if len(raw) < 64:
        return None
    try:
        if len(raw) == 64:
            return bytes.fromhex(raw).rstrip(b"\x00").decode("utf-8", errors="replace").strip() or None
        offset = int(raw[:64], 16) * 2
        if offset + 64 > len(raw):
            return None
        length = int(raw[offset:offset + 64], 16) * 2
        body = raw[offset + 64:offset + 64 + length]
        return bytes.fromhex(body).decode("utf-8", errors="replace").strip() or None
    except (ValueError, UnicodeDecodeError):
        return None


def decode_abi_uint(hex_data: str) -> int | None:
    if not hex_data or not hex_data.startswith("0x"):
        return None
    try:
        return int(hex_data, 16)
    except ValueError:
        return None


def evm_token_metadata(chain_name: str, chain: dict[str, str], address: str) -> dict[str, Any]:
    selectors = {
        "name": ("0x06fdde03", decode_abi_string),
        "symbol": ("0x95d89b41", decode_abi_string),
        "decimals": ("0x313ce567", decode_abi_uint),
        "total_supply": ("0x18160ddd", decode_abi_uint),
    }
    meta: dict[str, Any] = {"chain": chain_name, "chain_id": chain["chain_id"], "address": address}
    for key, (selector, decoder) in selectors.items():
        try:
            raw = evm_rpc(chain, "eth_call", [{"to": address, "data": selector}, "latest"], timeout=8)
            decoded = decoder(raw)
            if decoded is not None:
                meta[key] = decoded
        except Exception:
            continue
    if meta.get("decimals") is not None and meta.get("total_supply") is not None:
        try:
            meta["total_supply_ui"] = float(meta["total_supply"]) / (10 ** int(meta["decimals"]))
        except (TypeError, ValueError, OverflowError):
            pass
    return meta


def scan_evm_address(address: str, only_chain: str | None = None) -> list[dict[str, Any]]:
    chains = {only_chain: EVM_CHAINS[only_chain]} if only_chain in EVM_CHAINS else EVM_CHAINS
    results: list[dict[str, Any]] = []
    for name, chain in chains.items():
        row: dict[str, Any] = {
            "chain": name,
            "chain_id": chain["chain_id"],
            "native": chain["native"],
            "explorer": chain["explorer"].format(address=address),
        }
        try:
            code = evm_rpc(chain, "eth_getCode", [address, "latest"], timeout=8)
            row["is_contract"] = bool(code and code != "0x")
            row["code_size_bytes"] = max((len(str(code)) - 2) // 2, 0) if row["is_contract"] else 0
            row["code_prefix"] = str(code)[:10] if row["is_contract"] else ""
            row["is_delegated_account"] = bool(row["is_contract"] and row["code_size_bytes"] == 23 and str(code).lower().startswith("0xef0100"))
        except Exception as exc:  # noqa: BLE001
            row["error"] = f"getCode failed: {exc}"
        try:
            balance_hex = evm_rpc(chain, "eth_getBalance", [address, "latest"], timeout=8)
            row["native_balance"] = wei_to_native(str(balance_hex))
        except Exception as exc:  # noqa: BLE001
            row["balance_error"] = f"getBalance failed: {exc}"
        if row.get("is_contract") and not row.get("is_delegated_account"):
            row["token_metadata"] = evm_token_metadata(name, chain, address)
        results.append(row)
    return results


def opensanctions_public_check(query: str) -> dict[str, Any]:
    url = "https://www.opensanctions.org/search/?" + urllib.parse.urlencode({"q": query, "scope": "sanctions"})
    try:
        raw = http_text(url, timeout=12)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "degraded": True, "url": url, "error": str(exc)}
    text = html.unescape(re.sub(r"<[^>]+>", " ", raw))
    count = 0
    match = re.search(r"\b1\s*-\s*\d+\s*of\s+(\d+)\b", text, flags=re.IGNORECASE)
    if match:
        try:
            count = int(match.group(1))
        except ValueError:
            count = 0
    exact = count > 0 and query.lower() in text.lower()
    topics = sorted(set(re.findall(r"title=\"([^\"]*(?:Sanctioned|Terrorism|Cyber|Crime)[^\"]*)\"", raw, flags=re.IGNORECASE)))[:6]
    sources = sorted(set(re.findall(r'title="([^"]*(?:OFAC|Sanction|Crypto Wallets|FBI|OFSI|EU Financial)[^"]*)"', raw, flags=re.IGNORECASE)))[:6]
    return {"ok": True, "degraded": False, "url": url, "exact_mention": exact, "count_hint": count, "topics": topics, "sources": sources}


def onchainos_status() -> dict[str, Any]:
    binary = shutil.which("onchainos")
    if not binary:
        return {"available": False, "error": "onchainos not installed"}
    proc = subprocess.run([binary, "--version"], check=False, text=True, capture_output=True, timeout=10)
    return {"available": proc.returncode == 0, "binary": binary, "version": proc.stdout.strip() or proc.stderr.strip()}


def run_onchainos_token_scan(tokens: str, status: dict[str, Any]) -> dict[str, Any]:
    if not tokens:
        return {"available": False, "degraded": False, "reason": "no token contract detected on scanned chains", "tokens": tokens}
    if not status.get("available") or not status.get("binary"):
        return {
            "available": False,
            "degraded": True,
            "reason": status.get("error") or status.get("version") or "onchainos token-scan unavailable",
            "tokens": tokens,
        }
    proc = subprocess.run(
        [str(status["binary"]), "security", "token-scan", "--tokens", tokens],
        check=False,
        text=True,
        capture_output=True,
        timeout=45,
    )
    raw = (proc.stdout or proc.stderr or "").strip()
    try:
        payload: Any = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        payload = {"raw": raw[:1200]}
    if proc.returncode != 0:
        reason = payload.get("error") if isinstance(payload, dict) else raw[:300]
        if "Invalid Authority" in str(reason) or "wallet login" in str(reason):
            reason = "OKX/onchainos auth unavailable for token-scan in read-only server context"
        return {"available": True, "degraded": True, "reason": reason or "onchainos token-scan failed", "tokens": tokens, "raw": payload}
    return {"available": True, "degraded": False, "tokens": tokens, "raw": payload}


def collect_address_analysis(query: str, base_url: str = DEFAULT_BASE_URL, chain: str | None = None) -> dict[str, Any]:
    detected = detect_address_kind(query)
    warnings = crypto_risk_warnings(query)
    result: dict[str, Any] = {
        "input": query,
        "detected": detected,
        "crypto_risk": {
            "warnings": warnings,
            "needs_address_level_check": bool(warnings) or detected.get("ok"),
        },
        "onchainos": onchainos_status(),
        "verdict": "unknown",
        "errors": [],
    }
    if not detected.get("ok"):
        result["verdict"] = "unknown"
        result["errors"].append("No supported crypto address format detected.")
        return result

    address = str(detected["address"])
    try:
        result["opensanctions"] = opensanctions_public_check(address)
    except Exception as exc:  # noqa: BLE001
        result["opensanctions"] = {"ok": False, "degraded": True, "error": str(exc)}

    if detected.get("family") == "evm":
        evm = scan_evm_address(address, only_chain=chain)
        result["evm"] = evm
        contract_chains = [row for row in evm if row.get("is_contract") and not row.get("is_delegated_account")]
        delegated_chains = [row for row in evm if row.get("is_delegated_account")]
        rpc_ok = any("error" not in row for row in evm)
        result["type"] = "contract" if contract_chains else ("smart-account" if delegated_chains else ("wallet" if rpc_ok else "unknown"))
        result["contract_chains"] = [row["chain"] for row in contract_chains]
        result["delegated_chains"] = [row["chain"] for row in delegated_chains]
        result["native_balances"] = [
            {"chain": row["chain"], "symbol": row["native"], "balance": row.get("native_balance", 0), "explorer": row.get("explorer")}
            for row in evm if float(row.get("native_balance") or 0) > 0
        ]
        token_scan_tokens = ",".join(f"{row['chain_id']}:{address}" for row in contract_chains[:8])
        if contract_chains:
            result["token_security"] = run_onchainos_token_scan(token_scan_tokens, result["onchainos"])
        else:
            result["token_security"] = {
                "available": False,
                "degraded": False,
                "reason": "no token contract detected on scanned chains",
                "tokens": "",
            }
    else:
        kind = str(detected.get("kind"))
        explorer = NON_EVM_EXPLORERS.get(kind)
        result["type"] = f"{detected.get('family')}-address"
        result["explorers"] = [explorer.format(address=address)] if explorer else []

    os_hit = bool((result.get("opensanctions") or {}).get("count_hint"))
    substantive_warnings = [w for w in warnings if w.get("term") != "crypto-address"]
    high_warning = any(w.get("severity") == "high" for w in substantive_warnings)
    degraded_sources = bool((result.get("opensanctions") or {}).get("degraded"))
    if os_hit or high_warning:
        result["verdict"] = "high-risk"
    elif substantive_warnings:
        result["verdict"] = "risky"
    elif degraded_sources:
        result["verdict"] = "unknown"
    else:
        result["verdict"] = "clean-ish"
    result["caveat"] = "Read-only screening. Not legal/compliance clearance; use address-level sanctions and chain analytics before acting."
    return result


def format_radar_text(payload: dict[str, Any]) -> str:
    parts = ["OSINT / Risk radar", _line("time", payload.get("timestamp", "n/a")), _line("base", payload.get("base_url", "n/a"))]
    health = payload.get("health", {})
    gdelt_meta = payload.get("gdelt_meta") or {}
    gdelt_total = int(gdelt_meta.get("total") or 0)
    gdelt_errors = gdelt_meta.get("errors") or []
    quality = _quality_label(gdelt_meta)
    best = _best_signal(payload)
    best_text = _clip((best or {}).get("name") or (best or {}).get("title") or (best or {}).get("id") or "значимых сигналов нет", 95)
    health_text = health.get("status") if health.get("ok") else f"FAIL {_clip(health.get('error', ''), 90)}"
    parts.append(_line("health", health_text))

    parts.append("\nTL;DR")
    parts.append(f"1) OSIRIS {'живой' if health.get('ok') else 'недоступен'}; GDELT status: {quality}.")
    source_mode = gdelt_meta.get("source_mode") or "unknown"
    gdelt_scope = "fallback-срез" if source_mode == "fallback_only" else "GDELT-срез"
    parts.append(f"2) Рабочий {gdelt_scope}: {gdelt_total} событий; mode={source_mode}.")
    parts.append(f"3) Главный сигнал сейчас: {best_text}.")

    parts.append("\nИсточники и качество данных")
    parts.append(f"- GDELT: {quality}; raw_total={gdelt_total}; source={gdelt_meta.get('source') or 'unknown'}")
    parts.append(f"- GDELT upstream: {_upstream_summary(gdelt_meta.get('upstream_status') or {})}; 429_hits={gdelt_meta.get('rate_limit_hits', 0)}; timeout_hits={gdelt_meta.get('timeout_hits', 0)}")
    if gdelt_meta.get("circuit_open_until"):
        parts.append(f"- circuit breaker открыт до {gdelt_meta.get('circuit_open_until')}")
    if gdelt_errors:
        parts.append("- upstream_errors: " + "; ".join(_clip(err, 80) for err in gdelt_errors[:4]))
    parts.append(f"- Telegram/RSS: {len(payload.get('news') or [])} ранжированных сигналов")
    parts.append(f"- CISA KEV: {len(payload.get('kev') or [])} свежих CVE/KEV")

    parts.append("\nСводка сигналов")
    gdelt = payload.get("gdelt") or []
    gdelt_prefix = "Fallback" if gdelt_meta.get("fallback") or source_mode == "fallback_only" else "GDELT"
    if not gdelt:
        parts.append(f"- [{gdelt_prefix}] нет ранжированных событий")
    for item in gdelt[:5]:
        parts.append(_signal_line(gdelt_prefix, item))

    news = payload.get("news") or []
    if source_mode == "fallback_only":
        parts.append("- [Telegram/RSS] уже используется как fallback для GDELT")
    else:
        for item in news[:3]:
            parts.append(_signal_line("Telegram/RSS", item))

    kev = payload.get("kev") or []
    for item in kev[:3]:
        parts.append(f"- [CISA KEV] {item.get('id')} | {item.get('vendor')} {item.get('product')} | added {item.get('date')}")

    partial = quality != "GDELT OK"
    parts.append("\nРежим принятия решения")
    parts.append("- Торг: нет, пока сигнал не прошел кросс-чек вне GDELT.")
    parts.append(f"- Ожидание: {'да' if partial else 'умеренно'}; повторить сбор через {'10-20' if partial else '30-60'} минут.")
    parts.append("- Смотреть: да; приоритет - energy/geopolitics, sanctions, crypto/cyber, CVE.")

    parts.append("\nСледующий шаг и вывод")
    if partial:
        parts.append("1) Повторить radar после паузы, не разгоняя GDELT частыми запросами.")
        parts.append("2) Подтвердить топ-сигналы через Telegram/RSS или первоисточник.")
        verdict = "Ожидание с активной верификацией"
    else:
        parts.append("1) Держать текущий срез как рабочий baseline.")
        parts.append("2) Перепроверять только сигналы с высоким score или прямым market impact.")
        verdict = "Рабочее наблюдение"

    errors = {k: v for k, v in payload.items() if k.endswith("_error") and v}
    if errors:
        parts.append("\nОшибки адаптеров")
        for key, val in errors.items():
            parts.append(f"- {key}: {_clip(val, 120)}")
    parts.append(f"\nВердикт: режим - {verdict}.")
    return "\n".join(parts)


def run_cmd_json(cmd: list[str]) -> Any:
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def collect_inventory() -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    try:
        proc = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"], check=False, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "\t" in line:
                    name, version = line.split("\t", 1)
                    items.append({"ecosystem": "dpkg", "name": name, "version": version})
    except Exception:
        pass
    npm = run_cmd_json(["npm", "ls", "-g", "--depth=0", "--json"])
    if isinstance(npm, dict):
        for name, meta in (npm.get("dependencies") or {}).items():
            items.append({"ecosystem": "npm-global", "name": name, "version": str((meta or {}).get("version", ""))})
    try:
        proc = subprocess.run([sys.executable, "-m", "pip", "list", "--format=json"], check=False, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            for row in json.loads(proc.stdout):
                items.append({"ecosystem": "pip", "name": row.get("name", ""), "version": row.get("version", "")})
    except Exception:
        pass
    return items


def load_inventory_from_files(dpkg_path: Path, npm_path: Path, pip_path: Path) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if dpkg_path.exists():
        for line in dpkg_path.read_text().splitlines():
            if "\t" in line:
                name, version = line.split("\t", 1)
                items.append({"ecosystem": "dpkg", "name": name, "version": version})
    if npm_path.exists():
        data = json.loads(npm_path.read_text())
        for name, meta in (data.get("dependencies") or {}).items():
            items.append({"ecosystem": "npm", "name": name, "version": str((meta or {}).get("version", ""))})
    if pip_path.exists():
        for row in json.loads(pip_path.read_text()):
            items.append({"ecosystem": "pip", "name": row.get("name", ""), "version": row.get("version", "")})
    return items


def _package_match_terms(package_name: str) -> list[str]:
    lower = package_name.lower().split(":", 1)[0]
    if lower in GENERIC_PACKAGE_NAMES:
        return []
    normalized = re.sub(r"^(lib|python3-|node-)", "", lower)
    terms = {lower, normalized}
    terms.update(PACKAGE_ALIASES.get(lower, []))
    terms.update(PACKAGE_ALIASES.get(normalized, []))
    return sorted(t for t in terms if len(t) >= 3 and t not in GENERIC_PACKAGE_NAMES)


def _contains_term(haystack: str, term: str) -> bool:
    if any(ch in term for ch in ".+-"):
        return term in haystack
    return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", haystack) is not None


def match_cve_to_inventory(cve: dict[str, Any], inventory: list[dict[str, str]], limit: int = 20) -> list[dict[str, str]]:
    haystack = " ".join([
        str(cve.get("id", "")),
        str(cve.get("description", "")),
        json.dumps(cve.get("affected", []), ensure_ascii=False),
    ]).lower()
    matches = []
    for item in inventory:
        terms = _package_match_terms(item.get("name", ""))
        matched_terms = [term for term in terms if _contains_term(haystack, term)]
        if matched_terms:
            copy = dict(item)
            copy["match_basis"] = "package-or-alias-in-cve-metadata"
            copy["matched_terms"] = ",".join(matched_terms[:5])
            matches.append(copy)
    return matches[:limit]


def audit_osiris_repo(repo: Path) -> dict[str, Any]:
    middleware = repo / "src" / "middleware.ts"
    webhook = repo / "src" / "app" / "api" / "github-webhook" / "route.ts"
    docker_compose = repo / "docker-compose.yml"
    next_config = repo / "next.config.ts"
    mw_text = middleware.read_text(errors="ignore") if middleware.exists() else ""
    wh_text = webhook.read_text(errors="ignore") if webhook.exists() else ""
    docker_text = docker_compose.read_text(errors="ignore") if docker_compose.exists() else ""
    next_text = next_config.read_text(errors="ignore") if next_config.exists() else ""
    return {
        "repo": str(repo),
        "webhook_disabled": "webhook disabled" in wh_text.lower() and "100.68.100.15" not in wh_text,
        "umami_disabled": "umami-umami-1" not in mw_text and "/api/send" not in mw_text,
        "docker_has_external_umami": "umami_default" in docker_text,
        "docker_exposes_intel_publicly": "4000:4000" in docker_text,
        "docker_has_host_gateway": "host-gateway" in docker_text,
        "next_ignores_ts_build_errors": "ignoreBuildErrors" in next_text and "true" in next_text,
        "scanner_route_exists": (repo / "src" / "app" / "api" / "scanner" / "route.ts").exists(),
        "recommendations": [
            "run bound to 127.0.0.1 only",
            "do not expose scanner/osint endpoints publicly without auth",
            "prefer wrapper scripts over Docker compose defaults",
            "keep AIBTC/trading/public-post paths isolated",
        ],
    }


def github_reflection(repo: Path) -> dict[str, Any]:
    def git(args: list[str]) -> str:
        proc = subprocess.run(["git", "-C", str(repo), *args], check=False, capture_output=True, text=True, timeout=20)
        return proc.stdout.strip() if proc.returncode == 0 else ""
    status = git(["status", "--short"])
    remote = git(["remote", "get-url", "origin"])
    branch = git(["branch", "--show-current"])
    head = git(["rev-parse", "--short", "HEAD"])
    data: dict[str, Any] = {"repo": str(repo), "branch": branch, "head": head, "remote": remote, "dirty": bool(status), "status": status.splitlines()}
    if "github.com" in remote:
        owner_repo = re.sub(r".*github.com[:/]", "", remote).removesuffix(".git")
        data["github_owner_repo"] = owner_repo
        try:
            meta = http_json(f"https://api.github.com/repos/{owner_repo}", timeout=15)
            data["remote_default_branch"] = meta.get("default_branch")
            data["remote_pushed_at"] = meta.get("pushed_at")
            data["remote_open_issues"] = meta.get("open_issues_count")
            data["remote_stars"] = meta.get("stargazers_count")
            data["remote_license"] = (meta.get("license") or {}).get("spdx_id")
        except Exception as exc:  # noqa: BLE001
            data["github_error"] = str(exc)
    return data


def smoke(base_url: str, repo: Path) -> dict[str, Any]:
    radar = collect_radar(base_url)
    audit = audit_osiris_repo(repo) if repo.exists() else {"error": f"repo missing: {repo}"}
    gdelt_meta = radar.get("gdelt_meta") or {}
    gdelt_total = int(gdelt_meta.get("total") or 0)
    gdelt_errors = gdelt_meta.get("errors") or []
    checks = {
        "health_ok": bool(radar.get("health", {}).get("ok")),
        "gdelt_endpoint_ok": "gdelt_error" not in radar,
        "gdelt_has_events": gdelt_total > 0,
        "gdelt_degraded": gdelt_total == 0,
        "gdelt_upstream_errors": bool(gdelt_errors),
        "news_adapter_callable": "news_error" not in radar,
        "kev_adapter_callable": "kev_error" not in radar,
        "webhook_disabled": bool(audit.get("webhook_disabled")),
        "umami_disabled": bool(audit.get("umami_disabled")),
    }
    hard_checks = [
        checks["health_ok"],
        checks["gdelt_endpoint_ok"],
        checks["news_adapter_callable"],
        checks["kev_adapter_callable"],
        checks["webhook_disabled"],
        checks["umami_disabled"],
    ]
    return {"ok": all(hard_checks), "checks": checks, "radar": radar, "repo_audit": audit}


def print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes OSIRIS intelligence wrapper")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health")
    radar_p = sub.add_parser("radar")
    radar_p.add_argument("--json", action="store_true")
    smoke_p = sub.add_parser("smoke")
    smoke_p.add_argument("--repo", default="/root/labs/osiris")
    san_p = sub.add_parser("sanctions")
    san_p.add_argument("query")
    san_p.add_argument("--limit", default="10")
    addr_p = sub.add_parser("address")
    addr_p.add_argument("query")
    addr_p.add_argument("--chain", choices=sorted(EVM_CHAINS), default=None)
    wallet_p = sub.add_parser("wallet")
    wallet_p.add_argument("query")
    wallet_p.add_argument("--chain", choices=sorted(EVM_CHAINS), default=None)
    contract_p = sub.add_parser("contract")
    contract_p.add_argument("query")
    contract_p.add_argument("--chain", choices=sorted(EVM_CHAINS), default=None)
    cve_p = sub.add_parser("cve")
    cve_p.add_argument("cve")
    kev_p = sub.add_parser("kev")
    kev_p.add_argument("--days", type=int, default=30)
    mstr_p = sub.add_parser("mstr")
    mstr_p.add_argument("--json", action="store_true")
    mstr_p.add_argument("--limit", type=int, default=6)
    inv_p = sub.add_parser("inventory")
    inv_p.add_argument("--json", action="store_true")
    impact_p = sub.add_parser("local-cve-impact")
    impact_p.add_argument("cve")
    audit_p = sub.add_parser("audit-repo")
    audit_p.add_argument("--repo", default="/root/labs/osiris")
    gh_p = sub.add_parser("github-reflection")
    gh_p.add_argument("--repo", default="/root/labs/osiris")

    args = parser.parse_args(argv)
    if args.cmd == "health":
        print_json(local_api(args.base_url, "/api/health"))
    elif args.cmd == "radar":
        data = collect_radar(args.base_url)
        print_json(data) if args.json else print(format_radar_text(data))
    elif args.cmd == "smoke":
        data = smoke(args.base_url, Path(args.repo))
        print_json(data)
        return 0 if data.get("ok") else 2
    elif args.cmd == "sanctions":
        data = local_api(args.base_url, "/api/osint/sanctions", {"query": args.query, "limit": args.limit}, timeout=35)
        print_json(enrich_sanctions_result(data, args.query))
    elif args.cmd in {"address", "wallet", "contract"}:
        print_json(collect_address_analysis(args.query, base_url=args.base_url, chain=args.chain))
    elif args.cmd == "cve":
        try:
            print_json(local_api(args.base_url, "/api/osint/cve", {"cve": args.cve}, timeout=20))
        except HttpJsonError as exc:
            print_json({"ok": False, "status": exc.status, "error": exc._message(), "payload": exc.payload})
            return 2
    elif args.cmd == "kev":
        print_json(fetch_cisa_kev(days=args.days))
    elif args.cmd == "mstr":
        data = collect_mstr_watch(limit=args.limit)
        print_json(data) if args.json else print_json(data)
    elif args.cmd == "inventory":
        inv = collect_inventory()
        if args.json:
            print_json(inv)
        else:
            for item in inv:
                print(f"{item['ecosystem']}\t{item['name']}\t{item['version']}")
    elif args.cmd == "local-cve-impact":
        try:
            cve = local_api(args.base_url, "/api/osint/cve", {"cve": args.cve}, timeout=20)
        except HttpJsonError as exc:
            print_json({"ok": False, "status": exc.status, "error": exc._message(), "payload": exc.payload})
            return 2
        print_json({"cve": cve, "local_matches": match_cve_to_inventory(cve, collect_inventory())})
    elif args.cmd == "audit-repo":
        print_json(audit_osiris_repo(Path(args.repo)))
    elif args.cmd == "github-reflection":
        print_json(github_reflection(Path(args.repo)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HttpJsonError as exc:
        print_json({"ok": False, "status": exc.status, "error": exc._message(), "payload": exc.payload})
        raise SystemExit(2)
    except urllib.error.URLError as exc:
        print(f"OSIRIS intel error: {exc}", file=sys.stderr)
        raise SystemExit(2)
