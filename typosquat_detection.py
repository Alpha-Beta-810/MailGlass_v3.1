"""
typosquat_detection.py
-----------------------
Detects domains that impersonate a well-known brand through classic
typosquatting techniques:

  * character substitution   - "micr0soft.com", "g00gle.com", "paypa1.com"
  * combosquatting           - "mckinsey-login.com", "paypal-secure.net"
  * suffix/TLD swap          - "mckinsey.net" instead of "mckinsey.com"

This is a *pattern-level* heuristic, deliberately separate from
``domain_intel.detect_homograph_risk``: homograph detection catches
Unicode/script-mixing spoofing (e.g. Cyrillic "a"), while this module
catches plain-ASCII lookalikes that a human eye can easily miss but which
never involve mixed scripts at all - exactly the gap called out in that
module's own test suite (``mckinsey-login.com`` passes the homograph
check but is precisely what this module is for).

Brand list - hybrid, by design
===============================
Comparing every checked domain against the whole ~300-entry
``domainsInSubdomains`` whitelist would be cheap to run but noisy to
read: many of those entries are generic tracking/redirect domains, and
similarity-matching against all of them invites false positives. Instead:

  1. A curated shortlist of the brands most commonly impersonated in
     real-world phishing (``CURATED_BRANDS`` below) is always checked.
  2. Anything listed under an optional ``"typosquatBrands"`` key in
     ``whitelist.json`` is checked too, so a project owner can opt a
     handful of additional brands in (e.g. their own employer) without
     the noise of comparing against the full trusted-domain list.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from whitelist_utils import get_root_domain, is_subdomain_of_trusted, is_whitelisted, normalize_domain

# Brands most frequently impersonated in phishing campaigns. Kept as root
# domains (label + suffix) so they can be split into (label, suffix) pairs
# the same way a candidate domain is.
CURATED_BRANDS: Tuple[str, ...] = (
    "microsoft.com", "google.com", "apple.com", "amazon.com", "paypal.com",
    "dropbox.com", "adobe.com", "linkedin.com", "facebook.com", "instagram.com",
    "github.com", "netflix.com", "outlook.com", "office.com", "icloud.com",
    "docusign.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "americanexpress.com", "ebay.com", "walmart.com", "usps.com", "fedex.com",
    "ups.com", "mckinsey.com",
)

# Below this many characters in the brand label, single-character edit
# distance is enforced strictly (short labels like "ups" or "x" would
# otherwise match almost anything within distance 2).
_SHORT_LABEL_MAX_LEN = 4


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance between two short strings (domain labels)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def _max_allowed_distance(label: str) -> int:
    """Scale the edit-distance tolerance to the brand label's length.

    Short labels get a tight tolerance to avoid false positives; longer
    labels can absorb a couple of character swaps and still be an obvious
    impersonation attempt (e.g. "microsoft" -> "micr0soft").
    """
    length = len(label)
    if length <= _SHORT_LABEL_MAX_LEN:
        return 1
    if length <= 8:
        return 2
    return 3


def _split_label_suffix(root_domain: str) -> Tuple[str, str]:
    """Split an already-computed root domain into (label, suffix).

    ``root_domain`` is expected to already be the output of
    :func:`whitelist_utils.get_root_domain`, so this is a simple split on
    the first dot rather than a full public-suffix walk.
    """
    if "." not in root_domain:
        return root_domain, ""
    label, _, suffix = root_domain.partition(".")
    return label, suffix


def get_brand_domains(whitelist: Optional[Dict] = None) -> List[str]:
    """Return the full set of brand root domains to check against.

    Curated shortlist plus any project-specific additions under
    ``whitelist["typosquatBrands"]``.
    """
    brands = set(CURATED_BRANDS)
    if whitelist:
        for extra in whitelist.get("typosquatBrands", []):
            normalized = normalize_domain(extra)
            if normalized:
                brands.add(normalized)
    return sorted(brands)


def detect_typosquat(domain: str, whitelist: Optional[Dict] = None) -> Tuple[bool, str]:
    """Check whether ``domain`` looks like it's impersonating a known brand.

    Args:
        domain: A hostname (sender or link domain), not a full URL.
        whitelist: Whitelist config; used both to source extra brands to
            check against and to skip domains that are already trusted
            (a legitimate subdomain of a trusted brand is never flagged).

    Returns:
        ``(is_typosquat, reason)``. ``reason`` is ``""`` when not flagged.
    """
    domain = normalize_domain(domain)
    if not domain or "." not in domain:
        return False, ""

    # Already explicitly trusted somewhere in the whitelist (any list, not
    # just the curated brand set) -> never flag it, full stop.
    if whitelist and is_whitelisted(f"https://{domain}", whitelist):
        return False, ""

    candidate_root = get_root_domain(domain)
    candidate_label, candidate_suffix = _split_label_suffix(candidate_root)
    if not candidate_label:
        return False, ""

    for brand in get_brand_domains(whitelist):
        # Already a legitimate (sub)domain of this brand -> never flag it,
        # regardless of which list it came from.
        if is_subdomain_of_trusted(domain, brand):
            return False, ""

        brand_label, brand_suffix = _split_label_suffix(brand)
        if candidate_label == brand_label and candidate_suffix == brand_suffix:
            # Exact root-domain match to a brand not caught by the whitelist
            # subdomain check above just means it isn't marked trusted in
            # config - not a typosquat. Nothing to flag here.
            continue

        # 1) Suffix/TLD swap: identical label, different suffix.
        if candidate_label == brand_label and candidate_suffix != brand_suffix:
            return True, f"looks like '{brand}' but uses a different domain suffix ('.{candidate_suffix}')"

        # 2) Combosquatting: brand name plus an extra word, with or
        #    without a hyphen (mckinsey-login, mckinseysecurity, ...).
        if len(candidate_label) > len(brand_label) and (
            candidate_label.startswith(brand_label + "-")
            or candidate_label.startswith(brand_label)
            or candidate_label.endswith("-" + brand_label)
        ):
            return True, f"combines the trusted brand '{brand_label}' with extra text ('{candidate_label}')"

        # 3) Character-substitution typosquat (g00gle, micr0soft, paypa1).
        if abs(len(candidate_label) - len(brand_label)) <= _max_allowed_distance(brand_label):
            distance = _levenshtein(candidate_label, brand_label)
            if 0 < distance <= _max_allowed_distance(brand_label):
                return True, f"closely resembles trusted brand domain '{brand}' (edit distance {distance})"

    return False, ""


def scan_domains_for_typosquats(domains: List[str], whitelist: Optional[Dict] = None) -> List[str]:
    """Run :func:`detect_typosquat` over several domains, returning findings.

    Convenience helper for the orchestration layer: dedupes input and
    returns only the human-readable reasons for domains that were flagged.
    """
    findings: List[str] = []
    seen = set()
    for domain in domains:
        normalized = normalize_domain(domain)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        is_typosquat, reason = detect_typosquat(normalized, whitelist)
        if is_typosquat:
            findings.append(f"{normalized}: {reason}")
    return findings
