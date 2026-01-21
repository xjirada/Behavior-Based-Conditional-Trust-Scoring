
import re
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Tuple, List
from collections import defaultdict, deque

from trust_engine import Severity

WINDOW_SECONDS = 300
MAX_EVENTS_PER_KEY = 200


@dataclass
class EventFeatures:
    source_ip: str
    username: str
    endpoint: str
    category: str   
    raw: str
    ts: float



_recent_by_ip: Dict[str, deque] = defaultdict(deque)
_recent_by_user: Dict[str, deque] = defaultdict(deque)



SQLI_REGEX = re.compile(
    r"(?i)("
    r"union\s+select"
    r"|select\s+.+\s+from"
    r"|information_schema"
    r"|sleep\s*\("
    r"|benchmark\s*\("
    r")"
)

BOOLEAN_SQLI_REGEX = re.compile(
    r"(?i)(?:'|\")\s*or\s+1\s*=\s*1"
)

XSS_REGEX = re.compile(
    r"(?i)<script|onerror\s*=|onload\s*=|javascript:"
)
PATH_TRAVERSAL_REGEX = re.compile(r"\.\./")
LFI_REGEX = re.compile(r"(?i)(/etc/passwd|/proc/self/environ|php://|file://)")
AUTOMATION_KEYWORDS = [
    "sqlmap",
    "nmap",
    "ffuf",
    "dirbuster",
    "wpscan",
    "burpsuite",
]

ABUSIVE_WORDS = [
    "bodoh",
    "goblok",
    "tolol",
    "idiot",
    "stupid",
    "fuck",
]


def _cleanup_deque(dq: deque, now_ts: float) -> None:
    """Buang event yang udah keluar dari time window."""
    while dq and now_ts - dq[0].ts > WINDOW_SECONDS:
        dq.popleft()


def _base_content_score(raw: str, category: str, tags: List[str]) -> int:
    text = (raw or "").lower()
    score = 0

    if "human-ok" in text:
        tags.append("explicit-human-ok")
        return 0



    for tool in AUTOMATION_KEYWORDS:
        if tool in text:
            score += 60
            tags.append("automation-tool")


    if BOOLEAN_SQLI_REGEX.search(text):
        score += 50
        tags.append("sqli-boolean-1eq1")

    if SQLI_REGEX.search(text):
        score += 40
        tags.append("sqli-pattern")

   
    if XSS_REGEX.search(text):
        score += 40
        tags.append("xss-pattern")

   
    if PATH_TRAVERSAL_REGEX.search(text) or LFI_REGEX.search(text):
        score += 40
        tags.append("lfi/rfi-pattern")


    if "login failed" in text or "failed login" in text:
        score += 10
        tags.append("auth-failed-string")

    if "error" in text and "404" not in text:
        score += 5
        tags.append("generic-error")


    if category == "social":
        if any(bad in text for bad in ABUSIVE_WORDS):
            score += 8
            tags.append("abusive-language")

   
    if not text.strip():
        return 0

    if score == 0:
     
        score = 5
        tags.append("benign-or-exploratory")

    return score


def _score_to_severity(raw_score: int) -> Severity:
    """0–100 → Severity."""
    if raw_score <= 5:
        return Severity.SAFE
    if raw_score <= 25:
        return Severity.LOW
    if raw_score <= 50:
        return Severity.MEDIUM
    if raw_score <= 75:
        return Severity.HIGH
    return Severity.CRITICAL


def analyze_request(
    raw_text: str,
    source_ip: str,
    username: str,
    endpoint: str,
    category: str = "app",
) -> Tuple[Severity, Dict[str, Any]]:
    """
    Versi mini-SIEM:
    - Liat konten (regex & wordlist)
    - Liat rate / frekuensi per IP & user (brute force, scanning)
    - Kembalikan Severity + meta (tags, reason, raw_score, stats)
    """
    now = time.time()
    tags: List[str] = []


    ev = EventFeatures(
        source_ip=source_ip or "unknown",
        username=username or "anonymous",
        endpoint=endpoint or "unknown",
        category=category,
        raw=raw_text or "",
        ts=now,
    )


    ip_deque = _recent_by_ip[ev.source_ip]
    _cleanup_deque(ip_deque, now)
    ip_deque.append(ev)
    if len(ip_deque) > MAX_EVENTS_PER_KEY:
        ip_deque.popleft()

    # per user
    user_deque = _recent_by_user[ev.username]
    _cleanup_deque(user_deque, now)
    user_deque.append(ev)
    if len(user_deque) > MAX_EVENTS_PER_KEY:
        user_deque.popleft()


    raw_score = _base_content_score(ev.raw, ev.category, tags)


    ip_auth_events = [
        e for e in ip_deque
        if ("login" in e.raw.lower() or e.endpoint.endswith("/login"))
    ]
    user_auth_events = [
        e for e in user_deque
        if ("login" in e.raw.lower() or e.endpoint.endswith("/login"))
    ]


    if len(ip_auth_events) >= 5:
        raw_score += 25
        tags.append("bruteforce-ip")

    if len(user_auth_events) >= 5:
        raw_score += 20
        tags.append("bruteforce-user")


    unique_paths = {e.endpoint for e in ip_deque}
    if len(unique_paths) >= 8 and len(ip_deque) >= 15:
        raw_score += 20
        tags.append("path-scanning")


    if len(ip_deque) >= 4:
     
        last_four = list(ip_deque)[-4:]
        intervals = [
            last_four[i + 1].ts - last_four[i].ts
            for i in range(len(last_four) - 1)
        ]
        if intervals and max(intervals) < 0.8:
            raw_score += 20
            tags.append("automation-timing")

   
    raw_score = max(0, min(100, raw_score))
    severity = _score_to_severity(raw_score)

    
    meta = {
        "raw_score": raw_score,
        "tags": tags,
        "ip_event_count": len(ip_deque),
        "user_event_count": len(user_deque),
        "unique_paths_from_ip": list(unique_paths),
        "ip": ev.source_ip,
        "username": ev.username,
        "category": ev.category,
    }


    reason_parts = []
    if "automation-tool" in tags or "automation-timing" in tags:
        reason_parts.append("automation-like behavior detected")
    if "sqli-pattern" in tags:
        reason_parts.append("SQLi pattern found")
    if "xss-pattern" in tags:
        reason_parts.append("XSS pattern found")
    if "bruteforce-ip" in tags or "bruteforce-user" in tags:
        reason_parts.append("possible brute-force")
    if "abusive-language" in tags:
        reason_parts.append("abusive social language")
    if not reason_parts:
        reason_parts.append("no strong indicators, treated as low/benign")

    meta["reason"] = "; ".join(reason_parts)

    return severity, meta

