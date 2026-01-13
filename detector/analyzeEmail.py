# analyzeEmail.py
from __future__ import annotations

import hashlib
import html
import re
import sys
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, unquote

# ---------------------------
# Helpers: datatypes
# ---------------------------

@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str

@dataclass
class LinkInfo:
    raw: str
    normalized: str
    display_text: Optional[str]
    host: Optional[str]
    registrable_domain: Optional[str]
    flags: List[str]

@dataclass
class AnalysisResult:
    verdict: str               # safe | cautious | unsafe
    score: int                 # 0-100
    reasons: List[str]         # human-readable summary
    signals: Dict[str, Any]    # structured signals
    links: List[Dict[str, Any]]
    attachments: List[Dict[str, Any]]
    headers: Dict[str, Any]    # selected headers, sanitized


# ---------------------------
# Core: Load + Parse Email
# ---------------------------

def load_email_message(eml_path: Path):
    """Parse a .eml file into an EmailMessage with sane defaults."""
    raw = eml_path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg


def get_header(msg, name: str) -> Optional[str]:
    val = msg.get(name)
    if val is None:
        return None
    # EmailMessage can return header objects; normalize to str
    return str(val)


def extract_text_and_html(msg) -> Tuple[str, str]:
    """
    Return (text_plain, text_html).
    If multipart, prefer concatenation of parts.
    """
    text_parts: List[str] = []
    html_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            # skip container parts
            if part.is_multipart():
                continue

            ctype = part.get_content_type()
            disp = part.get_content_disposition()  # None / inline / attachment

            # attachments typically have a disposition, but sometimes "inline" with filename.
            filename = part.get_filename()

            # Only treat as body if not an attachment OR if it's inline without filename
            if disp == "attachment" or (filename is not None and disp in ("attachment", "inline")):
                continue

            try:
                payload = part.get_content()
            except Exception:
                # Fallback: decode bytes if needed
                payload_bytes = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                payload = payload_bytes.decode(charset, errors="replace")

            if ctype == "text/plain":
                text_parts.append(payload)
            elif ctype == "text/html":
                html_parts.append(payload)
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            payload_bytes = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            payload = payload_bytes.decode(charset, errors="replace")

        if ctype == "text/html":
            html_parts.append(payload)
        else:
            text_parts.append(payload)

    return ("\n".join(text_parts).strip(), "\n".join(html_parts).strip())


def extract_attachments(msg) -> List[AttachmentInfo]:
    attachments: List[AttachmentInfo] = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        if part.is_multipart():
            continue

        disp = part.get_content_disposition()
        filename = part.get_filename()
        if disp != "attachment" and not filename:
            continue

        filename = filename or "(no-filename)"
        content_type = part.get_content_type()

        data = part.get_payload(decode=True) or b""
        sha = hashlib.sha256(data).hexdigest()
        attachments.append(
            AttachmentInfo(
                filename=filename,
                content_type=content_type,
                size_bytes=len(data),
                sha256=sha,
            )
        )

    return attachments


# ---------------------------
# Links: extraction + normalization
# ---------------------------

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")  # zero-width chars
URL_RE = re.compile(r"(https?://[^\s<>\")]+)", re.IGNORECASE)

# Lightweight HTML href extractor (stdlib only)
HREF_RE = re.compile(r"""href\s*=\s*(['"])(.*?)\1""", re.IGNORECASE)

def normalize_url(url: str) -> str:
    """
    Normalize common phishing obfuscations:
    - HTML entity unescape
    - strip zero-width chars
    - percent-decode where safe
    - normalize scheme/host casing
    - remove trailing punctuation
    """
    u = url.strip()
    u = html.unescape(u)
    u = ZERO_WIDTH_RE.sub("", u)
    u = u.strip(").,;!\"'")  # common trailing punctuation

    # Parse and rebuild
    try:
        parsed = urlparse(u)
    except Exception:
        return u

    scheme = (parsed.scheme or "").lower()
    netloc = parsed.netloc

    # If someone writes "http://user@host" netloc contains userinfo
    # Keep netloc as-is but flag later.
    path = unquote(parsed.path)
    query = parsed.query
    fragment = parsed.fragment

    # Lowercase host portion if possible
    # netloc can be "user:pass@host:port"
    host = parsed.hostname.lower() if parsed.hostname else None
    port = f":{parsed.port}" if parsed.port else ""
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"

    if host:
        netloc = f"{userinfo}{host}{port}"

    return urlunparse((scheme, netloc, path, parsed.params, query, fragment))


def get_registrable_domain(host: Optional[str]) -> Optional[str]:
    """
    Best effort:
    - If tldextract is installed, use it (recommended).
    - Else fallback: last two labels (not perfect for co.uk etc).
    """
    if not host:
        return None

    try:
        import tldextract  # type: ignore
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return host
    except Exception:
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host


def extract_links(text_plain: str, text_html: str) -> List[LinkInfo]:
    links: List[LinkInfo] = []

    # From plain text
    for m in URL_RE.finditer(text_plain or ""):
        raw = m.group(1)
        norm = normalize_url(raw)
        parsed = urlparse(norm)
        host = parsed.hostname
        flags = []

        if parsed.username or "@" in parsed.netloc:
            flags.append("url_contains_userinfo_or_at")

        if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            flags.append("ip_address_host")

        if parsed.port and parsed.port not in (80, 443):
            flags.append("unusual_port")

        links.append(
            LinkInfo(
                raw=raw,
                normalized=norm,
                display_text=None,
                host=host,
                registrable_domain=get_registrable_domain(host),
                flags=flags,
            )
        )

    # From HTML hrefs
    # Capture href + (optional) attempt to capture nearby anchor text in a very lightweight way.
    # For V1: we'll just store display_text=None unless you later use BeautifulSoup.
    for m in HREF_RE.finditer(text_html or ""):
        raw = m.group(2)
        norm = normalize_url(raw)
        parsed = urlparse(norm)
        host = parsed.hostname
        flags = []

        if parsed.username or "@" in parsed.netloc:
            flags.append("url_contains_userinfo_or_at")

        if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            flags.append("ip_address_host")

        if parsed.port and parsed.port not in (80, 443):
            flags.append("unusual_port")

        links.append(
            LinkInfo(
                raw=raw,
                normalized=norm,
                display_text=None,
                host=host,
                registrable_domain=get_registrable_domain(host),
                flags=flags,
            )
        )

    # Deduplicate by normalized URL (keep first)
    seen = set()
    deduped: List[LinkInfo] = []
    for li in links:
        key = li.normalized
        if key in seen:
            continue
        seen.add(key)
        deduped.append(li)

    return deduped


# ---------------------------
# Scoring (V1: explainable rules)
# ---------------------------

def verdict_from_score(score: int) -> str:
    if score >= 60:
        return "unsafe"
    if score >= 25:
        return "cautious"
    return "safe"


def score_email(
    from_addr: Optional[str],
    reply_to: Optional[str],
    return_path: Optional[str],
    links: List[LinkInfo],
    attachments: List[AttachmentInfo],
    subject: Optional[str],
) -> Tuple[int, List[str], Dict[str, Any]]:
    score = 0
    reasons: List[str] = []
    signals: Dict[str, Any] = {}

    # Helper for extracting domain from header-ish string
    def domain_from_addr(s: Optional[str]) -> Optional[str]:
        if not s:
            return None
        m = re.search(r"@([A-Za-z0-9\.\-]+)", s)
        return m.group(1).lower() if m else None

    from_domain = domain_from_addr(from_addr)
    reply_domain = domain_from_addr(reply_to)
    return_domain = domain_from_addr(return_path)

    signals["from_domain"] = from_domain
    signals["reply_to_domain"] = reply_domain
    signals["return_path_domain"] = return_domain

    # Rule: Reply-To differs from From (common phishing pattern)
    if from_domain and reply_domain and reply_domain != from_domain:
        score += 18
        reasons.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).")

    # Rule: Return-Path differs from From (not always bad, but worth a small bump)
    if from_domain and return_domain and return_domain != from_domain:
        score += 6
        reasons.append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain}).")

    # Rule: suspicious subject keywords (small weight)
    subj = (subject or "").lower()
    suspicious_subject_terms = ["urgent", "verify", "password", "account", "invoice", "payment", "action required"]
    hit_terms = [t for t in suspicious_subject_terms if t in subj]
    if hit_terms:
        score += min(10, 2 * len(hit_terms))
        reasons.append(f"Subject contains suspicious terms: {', '.join(hit_terms)}.")
        signals["subject_terms"] = hit_terms

    # Link rules
    shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy"}
    link_flags_count: Dict[str, int] = {}

    for li in links:
        for f in li.flags:
            link_flags_count[f] = link_flags_count.get(f, 0) + 1

        if li.registrable_domain and li.registrable_domain in shorteners:
            score += 12
            reasons.append(f"Link uses a URL shortener ({li.registrable_domain}).")
            link_flags_count["url_shortener"] = link_flags_count.get("url_shortener", 0) + 1

        if "ip_address_host" in li.flags:
            score += 18
            reasons.append("Link points to an IP address host (common in phishing).")

        if "unusual_port" in li.flags:
            score += 12
            reasons.append("Link uses an unusual port (not 80/443).")

        if "url_contains_userinfo_or_at" in li.flags:
            score += 18
            reasons.append("Link contains userinfo/@ in the URL (obfuscation technique).")

    signals["link_flags_count"] = link_flags_count
    signals["link_count"] = len(links)

    # Attachment rules
    signals["attachment_count"] = len(attachments)
    for att in attachments:
        fn = att.filename.lower()
        ctype = att.content_type.lower()

        # Office macro-ish types / extensions
        if fn.endswith((".docm", ".xlsm", ".pptm")):
            score += 30
            reasons.append(f"Macro-enabled Office attachment detected: {att.filename}.")

        # Common risky patterns
        if fn.endswith((".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1")):
            score += 45
            reasons.append(f"Potentially executable attachment detected: {att.filename}.")

        # Archives: may contain nested payloads
        if fn.endswith((".zip", ".rar", ".7z")):
            score += 15
            reasons.append(f"Archive attachment detected (may hide payload): {att.filename}.")

        # Content-type mismatch suspicion (lightweight for V1)
        if fn.endswith(".pdf") and "pdf" not in ctype:
            score += 10
            reasons.append(f"Attachment content-type mismatch suspected for {att.filename}.")

    # Cap score
    score = min(100, score)
    return score, reasons, signals


# ---------------------------
# Public API: analyze_email()
# ---------------------------

def analyze_email(eml_path: Path) -> Dict[str, Any]:
    msg = load_email_message(eml_path)

    headers = {
        "from": get_header(msg, "From"),
        "to": get_header(msg, "To"),
        "subject": get_header(msg, "Subject"),
        "date": get_header(msg, "Date"),
        "message_id": get_header(msg, "Message-ID"),
        "reply_to": get_header(msg, "Reply-To"),
        "return_path": get_header(msg, "Return-Path"),
        "sender": get_header(msg, "Sender"),
        # Authentication-Results will matter later (SPF/DKIM/DMARC), capture now
        "authentication_results": get_header(msg, "Authentication-Results"),
    }

    text_plain, text_html = extract_text_and_html(msg)
    attachments = extract_attachments(msg)
    links = extract_links(text_plain, text_html)

    score, reasons, signals = score_email(
        from_addr=headers["from"],
        reply_to=headers["reply_to"],
        return_path=headers["return_path"],
        links=links,
        attachments=attachments,
        subject=headers["subject"],
    )

    verdict = verdict_from_score(score)

    result = AnalysisResult(
        verdict=verdict,
        score=score,
        reasons=reasons,
        signals=signals,
        links=[asdict(l) for l in links],
        attachments=[asdict(a) for a in attachments],
        headers=headers,
    )

    return asdict(result)


# Optional: allow running this module directly for quick testing
if __name__ == "__main__":
    import json
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("eml_path")
    args = p.parse_args()
    out = analyze_email(Path(args.eml_path))
    print(json.dumps(out, indent=2))
