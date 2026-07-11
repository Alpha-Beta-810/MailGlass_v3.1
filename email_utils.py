"""
email_utils.py
--------------
Parsing of raw .eml files into a structured, analysis-ready form.

Handles the messy realities of real-world email: multipart MIME, missing
headers, mixed encodings, and HTML bodies that need both their hyperlinks
*and* their visible text extracted (see ``url_utils`` for why those must be
kept separate).
"""

from __future__ import annotations

import email
import email.header
import email.utils
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from url_utils import (
    extract_urls_from_html,
    extract_urls_from_text,
    extract_visible_text,
    merge_urls,
)

logger = logging.getLogger(__name__)

_UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


@dataclass
class ParsedEmail:
    """Structured representation of a parsed .eml file."""

    filepath: str
    subject: str = ""
    sender: str = ""
    sender_domain: str = ""
    visible_text: str = ""
    candidate_urls: List[str] = field(default_factory=list)
    anchor_map: dict = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)

    # --- Header-based signals (Reply-To / Return-Path / SPF / DKIM / DMARC /
    # --- Received chain) - a second, independent line of evidence from the
    # --- URL/body/ML checks, since a forged "From" display name is easy but
    # --- forging every header along the delivery path is not.
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    received_hop_count: int = 0
    spf_result: str = ""      # "pass" / "fail" / "softfail" / "neutral" / "none" / ""
    dkim_result: str = ""     # "pass" / "fail" / "none" / ""
    dmarc_result: str = ""    # "pass" / "fail" / "none" / ""
    header_findings: List[str] = field(default_factory=list)


def _decode_header_value(raw_value: Optional[str], fallback: str = "") -> str:
    """Safely decode a MIME-encoded header (e.g. ``=?UTF-8?B?...?=``)."""
    if not raw_value:
        return fallback
    try:
        parts = email.header.decode_header(raw_value)
        decoded = ""
        for fragment, encoding in parts:
            if isinstance(fragment, bytes):
                decoded += fragment.decode(encoding or "utf-8", errors="replace")
            else:
                decoded += fragment
        return decoded
    except (email.errors.HeaderParseError, LookupError, ValueError) as exc:
        logger.debug("Header decode failed for %r: %s", raw_value, exc)
        return raw_value


def _extract_body_parts(msg: "email.message.Message") -> tuple[str, str]:
    """Walk a message's MIME parts and collect plain-text and HTML bodies.

    Returns:
        (plain_text_body, html_body) - either may be empty.
    """
    plain_text = ""
    html_text = ""

    try:
        parts = list(msg.walk()) if msg.is_multipart() else [msg]
    except Exception as exc:  # A truly malformed message shouldn't crash us.
        logger.warning("Failed to walk message parts: %s", exc)
        return plain_text, html_text

    for part in parts:
        content_type = part.get_content_type()
        # Skip attachments/containers; we only want inline text bodies here.
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition:
            continue

        try:
            payload = part.get_payload(decode=True)
        except Exception as exc:
            logger.debug("Could not decode a message part: %s", exc)
            continue

        if payload is None:
            continue

        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            decoded = payload.decode("utf-8", errors="replace")

        if content_type == "text/plain":
            plain_text += decoded
        elif content_type == "text/html":
            html_text += decoded

    return plain_text, html_text


def _domain_of(addr: str) -> str:
    """Best-effort domain extraction from a raw address/header value."""
    if not addr:
        return ""
    try:
        _, parsed_addr = email.utils.parseaddr(addr)
    except Exception:
        parsed_addr = addr
    candidate = parsed_addr or addr
    candidate = candidate.strip().strip("<>")
    if "@" in candidate:
        return candidate.split("@")[-1].strip().lower()
    return ""


_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)


def _extract_auth_results(msg: "email.message.Message") -> "tuple[str, str, str]":
    """Parse SPF/DKIM/DMARC verdicts out of Authentication-Results headers.

    Mail servers (Gmail, Outlook, etc.) stamp one or more
    ``Authentication-Results`` headers on inbound mail recording whether
    each check passed. There's no single standard header name/format, so
    this is deliberately a best-effort regex scan rather than a strict
    parser - a missing/malformed header just leaves the result as "" and
    contributes nothing to the score, rather than raising.
    """
    spf = dkim = dmarc = ""
    header_values = msg.get_all("Authentication-Results", []) or []
    # Some MTAs also stamp a standalone Received-SPF header.
    header_values += msg.get_all("Received-SPF", []) or []
    combined = " ".join(header_values)
    for check, result in _AUTH_RESULT_RE.findall(combined):
        result = result.lower()
        check = check.lower()
        if check == "spf" and not spf:
            spf = result
        elif check == "dkim" and not dkim:
            dkim = result
        elif check == "dmarc" and not dmarc:
            dmarc = result
    return spf, dkim, dmarc


def _extract_header_signals(msg: "email.message.Message", sender_domain: str) -> dict:
    """Pull Reply-To / Return-Path / auth-result / Received-chain signals.

    These are independent of the URL/body/ML checks: forging a display
    name is trivial, but forging every hop of the delivery path and every
    authentication header is much harder, so a mismatch here is a useful
    corroborating (or contradicting) signal.
    """
    reply_to_raw = msg.get("Reply-To", "") or ""
    return_path_raw = msg.get("Return-Path", "") or ""
    reply_to_domain = _domain_of(reply_to_raw)
    return_path_domain = _domain_of(return_path_raw)

    spf, dkim, dmarc = _extract_auth_results(msg)
    received_hop_count = len(msg.get_all("Received", []) or [])

    findings: List[str] = []
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        findings.append(
            f"Reply-To domain ({reply_to_domain}) differs from sender domain ({sender_domain})"
        )
    if return_path_domain and sender_domain and return_path_domain != sender_domain:
        findings.append(
            f"Return-Path domain ({return_path_domain}) differs from sender domain ({sender_domain})"
        )
    if spf == "fail":
        findings.append("SPF check failed on this message")
    if dkim == "fail":
        findings.append("DKIM check failed on this message")
    if dmarc == "fail":
        findings.append("DMARC check failed on this message")

    return {
        "reply_to": reply_to_raw,
        "reply_to_domain": reply_to_domain,
        "return_path": return_path_raw,
        "return_path_domain": return_path_domain,
        "received_hop_count": received_hop_count,
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "header_findings": findings,
    }


def parse_eml_file(filepath: str) -> ParsedEmail:
    """Parse a single .eml file into a :class:`ParsedEmail`.

    This never raises: any failure is recorded in ``parse_errors`` and the
    function returns as much information as it was able to recover, so a
    single malformed email doesn't stop analysis of the rest of the batch.

    Args:
        filepath: Path to the .eml file on disk.

    Returns:
        A populated ParsedEmail (possibly with empty fields and a non-empty
        ``parse_errors`` list if something went wrong).
    """
    result = ParsedEmail(filepath=filepath)

    try:
        with open(filepath, "rb") as f:
            raw_bytes = f.read()
    except OSError as exc:
        result.parse_errors.append(f"Could not read file: {exc}")
        return result

    try:
        msg = email.message_from_bytes(raw_bytes)
    except Exception as exc:
        result.parse_errors.append(f"Could not parse email structure: {exc}")
        return result

    result.subject = _decode_header_value(msg.get("Subject"), fallback="(No Subject)")

    from_header = msg.get("From", "")
    try:
        sender_name, sender_addr = email.utils.parseaddr(from_header)
        result.sender = sender_addr or from_header
    except Exception:
        result.sender = from_header
    if "@" in result.sender:
        result.sender_domain = result.sender.split("@")[-1].strip().lower()

    header_signals = _extract_header_signals(msg, result.sender_domain)
    result.reply_to = header_signals["reply_to"]
    result.reply_to_domain = header_signals["reply_to_domain"]
    result.return_path = header_signals["return_path"]
    result.return_path_domain = header_signals["return_path_domain"]
    result.received_hop_count = header_signals["received_hop_count"]
    result.spf_result = header_signals["spf_result"]
    result.dkim_result = header_signals["dkim_result"]
    result.dmarc_result = header_signals["dmarc_result"]
    result.header_findings = header_signals["header_findings"]

    plain_text, html_text = _extract_body_parts(msg)

    href_urls: List[str] = []
    anchor_map: dict = {}
    if html_text:
        href_urls, anchor_map = extract_urls_from_html(html_text)
        html_visible_text = extract_visible_text(html_text)
    else:
        html_visible_text = ""

    # Visible body: prefer the plain-text part (what most clients render by
    # default when both are present), falling back to the HTML's visible text.
    result.visible_text = (plain_text or html_visible_text).strip()

    text_urls = extract_urls_from_text(plain_text)
    subject_urls = extract_urls_from_text(result.subject)

    result.candidate_urls = merge_urls(href_urls, text_urls, subject_urls)
    result.anchor_map = anchor_map

    try:
        result.attachments = extract_attachments(msg)
    except Exception as exc:
        result.parse_errors.append(f"Attachment extraction failed: {exc}")

    return result


def extract_attachments(msg: "email.message.Message", save_dir: str = "attachments") -> List[str]:
    """Save any file attachments in ``msg`` to disk and return their paths.

    Filenames are sanitized to remove path-traversal and filesystem-unsafe
    characters. Errors saving an individual attachment are logged and
    skipped rather than raised.
    """
    saved_paths: List[str] = []
    try:
        os.makedirs(save_dir, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create attachments directory %s: %s", save_dir, exc)
        return saved_paths

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition") is None:
            continue

        filename = part.get_filename()
        if not filename:
            continue

        decoded_filename = _decode_header_value(filename, fallback=filename)
        safe_filename = _UNSAFE_FILENAME_CHARS.sub("_", decoded_filename)
        safe_filename = os.path.basename(safe_filename)  # defeat path traversal
        filepath = os.path.join(save_dir, safe_filename)

        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            with open(filepath, "wb") as f:
                f.write(payload)
            saved_paths.append(filepath)
        except OSError as exc:
            logger.warning("Could not save attachment %s: %s", filename, exc)

    return saved_paths
