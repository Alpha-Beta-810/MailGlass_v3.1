"""
whitelist_utils.py
-------------------
Domain normalization and whitelist matching.

The original implementation used plain substring matching
(``if whitelisted_domain in domain``), which is both too loose (it would
match "mckinsey.com" against "notmckinsey.com.evil.tld") and too strict
(it wouldn't recognise that "links.mckinsey.com" is a legitimate subdomain
of the trusted "mckinsey.com"). This module replaces that with proper
root-domain comparison.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# A short list of common multi-label public suffixes. This is not a full
# Public Suffix List (fetching/maintaining that requires a network call
# to publicsuffix.org), but it correctly handles the vast majority of
# real-world domains seen in phishing/legitimate mail without any external
# dependency or network access.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "co.in", "net.in", "org.in", "gov.in", "co.kr",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "com.br", "net.br", "org.br",
    "com.mx", "com.tr", "com.tw", "com.sg", "com.hk",
    "co.nz", "co.za", "co.il", "co.th", "co.id",
}


def normalize_domain(domain: str) -> str:
    """Lowercase a domain and strip a leading ``www.`` label.

    Args:
        domain: Raw hostname, e.g. ``"WWW.McKinsey.com"``.

    Returns:
        Normalized hostname, e.g. ``"mckinsey.com"``.
    """
    if not domain:
        return ""
    domain = domain.strip().lower()
    # Strip a userinfo/port if one slipped through (e.g. "user@host:443").
    domain = domain.split("@")[-1].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.rstrip(".")


def get_domain_from_url(url: str) -> str:
    """Extract and normalize the hostname from a URL or bare sender address."""
    try:
        netloc = urlparse(url).netloc
        if not netloc:
            # Not a full URL (e.g. a bare domain or "user@domain" sender).
            netloc = url
        return normalize_domain(netloc)
    except ValueError:
        return normalize_domain(url)


def get_root_domain(domain: str) -> str:
    """Return the registrable "root" domain for subdomain-aware comparison.

    Examples:
        ``links.mckinsey.com``    -> ``mckinsey.com``
        ``pages.careers.mckinsey.com`` -> ``mckinsey.com``
        ``mckinsey.co.uk``        -> ``mckinsey.co.uk``
        ``mckinsey-login.com``    -> ``mckinsey-login.com``  (unchanged;
             it is its own distinct root domain, and must NOT match
             "mckinsey.com")
    """
    domain = normalize_domain(domain)
    labels = domain.split(".")
    if len(labels) < 2:
        return domain

    last_two = ".".join(labels[-2:])
    if len(labels) >= 3 and last_two in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def is_subdomain_of_trusted(domain: str, trusted_domain: str) -> bool:
    """Check whether ``domain`` is the trusted domain or a genuine subdomain.

    Uses exact match or a strict ``".trusted_domain"`` suffix so that
    look-alike domains like ``mckinsey-login.com`` are correctly rejected
    even though they contain the trusted domain as a substring.
    """
    domain = normalize_domain(domain)
    trusted_domain = normalize_domain(trusted_domain)
    if not domain or not trusted_domain:
        return False
    return domain == trusted_domain or domain.endswith("." + trusted_domain)


def load_whitelist(filepath: str) -> Dict:
    """Load the whitelist configuration from disk.

    Returns an empty, well-formed whitelist structure (rather than raising)
    if the file is missing or invalid, so a bad config never crashes analysis.
    """
    default: Dict = {
        "exactMatching": {"url": [], "domain": []},
        "domainsInSubdomains": [],
        "domainsInURLs": [],
        "domainsInEmails": [],
    }
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key, value in default.items():
            data.setdefault(key, value)
        return data
    except FileNotFoundError:
        logger.warning("Whitelist file not found: %s. Using empty whitelist.", filepath)
        return default
    except json.JSONDecodeError as exc:
        logger.warning("Whitelist file %s is not valid JSON (%s). Using empty whitelist.", filepath, exc)
        return default


def _all_trusted_domains(whitelist: Dict) -> List[str]:
    """Flatten every domain-like list in the whitelist into one collection."""
    domains: List[str] = []
    domains.extend(whitelist.get("exactMatching", {}).get("domain", []))
    domains.extend(whitelist.get("domainsInSubdomains", []))
    domains.extend(whitelist.get("domainsInURLs", []))
    domains.extend(whitelist.get("domainsInEmails", []))
    return domains


def is_whitelisted(url: str, whitelist: Dict) -> bool:
    """Determine whether a URL's destination is a trusted domain.

    Performs, in order:
      1. Exact URL match.
      2. Root-domain + subdomain-aware match against every trusted domain
         list in the whitelist config.

    Look-alike domains such as ``mckinsey-login.com`` are never matched
    against a trusted ``mckinsey.com`` entry.

    Args:
        url: The (already validated) destination URL to check.
        whitelist: Whitelist config as returned by :func:`load_whitelist`.

    Returns:
        True if the URL should be treated as trusted and skipped.
    """
    if not url:
        return False

    if url in whitelist.get("exactMatching", {}).get("url", []):
        return True

    domain = get_domain_from_url(url)
    if not domain:
        return False

    for trusted in _all_trusted_domains(whitelist):
        if is_subdomain_of_trusted(domain, trusted):
            return True

    return False


def is_sender_whitelisted(sender_email: str, whitelist: Dict) -> bool:
    """Check whether the sender's domain is trusted (subdomain-aware)."""
    if not sender_email or "@" not in sender_email:
        return False
    sender_domain = normalize_domain(sender_email.split("@")[-1])
    for trusted in _all_trusted_domains(whitelist):
        if is_subdomain_of_trusted(sender_domain, trusted):
            return True
    return False
