"""
domain_intel.py
-----------------
Domain-level intelligence that goes beyond a single URL's reputation:

- WHOIS-based domain age. A domain registered days ago is a classic
  phishing tell (this wires up the "domain age < 30 days" hook that was
  reserved but unimplemented in risk_engine.py).
- IDN / punycode homograph detection. Flags lookalike domains that use
  Unicode characters visually mimicking a trusted brand (e.g. a Cyrillic
  "а" standing in for a Latin "a" in "аpple.com"), or raw punycode
  (xn--...) encoding.

Both are best-effort and fail safe: WHOIS lookups depend on network access
and registrar cooperation, so any failure (library missing, timeout, rate
limit, domain doesn't expose a creation date) returns None instead of
raising - it simply means that signal doesn't contribute to the score.
"""

from __future__ import annotations

import datetime
import logging
import unicodedata
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import whois as _whois_lib  # "python-whois" package
except ImportError:
    _whois_lib = None
    logger.debug("python-whois is not installed; domain-age checks will be skipped.")


def get_domain_age_days(domain: str) -> Optional[int]:
    """Best-effort WHOIS lookup for how many days ago a domain was registered.

    Args:
        domain: A bare hostname, e.g. ``"mckinsey-login.com"``.

    Returns:
        Age in days, or None if the lookup can't be completed for any
        reason (library not installed, network/timeout error, registrar
        doesn't expose WHOIS creation data, privacy-protected record, etc).
        Never raises.
    """
    if not domain or _whois_lib is None:
        return None

    try:
        record = _whois_lib.whois(domain)
        creation_date = getattr(record, "creation_date", None)
    except Exception as exc:  # WHOIS servers fail in many undocumented ways.
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None

    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None

    if isinstance(creation_date, datetime.date) and not isinstance(creation_date, datetime.datetime):
        creation_date = datetime.datetime.combine(creation_date, datetime.time())

    if not isinstance(creation_date, datetime.datetime):
        return None

    now = datetime.datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.datetime.now()
    return max((now - creation_date).days, 0)


def decode_idn_domain(domain: str) -> str:
    """Decode punycode (``xn--``) labels back to their Unicode form.

    Used to show a human-readable version of what a punycode domain
    actually displays as in a browser's address bar.

    Returns the domain unchanged if it isn't punycode or decoding fails.
    """
    if not domain or "xn--" not in domain:
        return domain

    decoded_labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                decoded_labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, LookupError):
                decoded_labels.append(label)
        else:
            decoded_labels.append(label)
    return ".".join(decoded_labels)


def _char_script(ch: str) -> Optional[str]:
    """Best-effort Unicode script family for a single character (e.g. "LATIN")."""
    try:
        return unicodedata.name(ch).split(" ")[0]
    except ValueError:
        return None


def detect_homograph_risk(domain: str) -> Tuple[bool, str]:
    """Flag domains that use punycode or mix multiple Unicode scripts.

    This is a pattern-level heuristic, not a per-domain blacklist: it
    catches the *technique* (visual spoofing via lookalike characters)
    regardless of which brand is being imitated.

    Args:
        domain: A bare hostname.

    Returns:
        (is_suspicious, reason). ``reason`` is an empty string when not
        suspicious.
    """
    if not domain:
        return False, ""

    if "xn--" in domain:
        decoded = decode_idn_domain(domain)
        return True, f"Punycode-encoded domain (displays as '{decoded}')"

    scripts = {script for ch in domain if ch.isalpha() for script in [_char_script(ch)] if script}
    if len(scripts) > 1:
        return True, f"Domain mixes multiple Unicode scripts: {', '.join(sorted(scripts))}"

    return False, ""
