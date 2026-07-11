"""
url_utils.py
------------
Utilities for extracting, validating, and resolving URLs found in emails.

This module fixes the core bug in the original implementation: URLs were
extracted from the *visible text* of an HTML email (after ``soup.get_text()``
had already thrown away every ``<a href="...">`` attribute). Anchor text like

    <a href="https://links.mckinsey.com/abc123">McKinsey.org</a>

would collapse to the plain string "McKinsey.org", which is not a URL at all
and was then sent to PhishTank, which correctly rejected it as malformed.

Here, hyperlinks are read directly from the HTML's ``href`` attributes, and
the visible text is extracted and kept *separately* for display / ML use.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Schemes that are not web destinations and should never be sent to a URL
# reputation service (PhishTank, VirusTotal URL scanning, etc.).
IGNORED_URL_SCHEMES = {"javascript", "mailto", "tel", "cid", "data", "file"}

# A conservative regex for finding "bare" URLs inside plain text bodies.
# It intentionally requires an explicit http:// or https:// scheme so that
# plain domain mentions ("McKinsey.org", "paypal.com") are not treated as
# clickable destinations - those are validated/rejected by is_valid_url too.
_PLAIN_TEXT_URL_RE = re.compile(
    r"""https?://[^\s<>"'\)\]]+""",
    re.IGNORECASE,
)

# Trailing punctuation that regex-based extraction commonly picks up by
# mistake (end of sentence, closing parenthesis carried over from prose, etc.)
_TRAILING_JUNK = ".,;:!?)]}\"'"


@dataclass
class ExtractedContent:
    """Container for everything pulled out of an email body.

    Attributes:
        visible_text: Human-readable text of the email (what a recipient
            would actually see), with all markup stripped.
        urls: De-duplicated list of candidate URLs gathered from both
            ``href`` attributes and plain-text scanning, in first-seen order.
        anchor_map: Mapping of destination URL -> visible anchor text, useful
            for flagging mismatches between what a link *says* and where it
            actually goes (a classic phishing tell).
    """

    visible_text: str
    urls: List[str] = field(default_factory=list)
    anchor_map: dict = field(default_factory=dict)


def _clean_trailing_punctuation(url: str) -> str:
    """Strip punctuation that regex extraction accidentally swallows.

    Balances parentheses so a URL legitimately containing "(" isn't
    mangled, e.g. Wikipedia-style links.
    """
    while url and url[-1] in _TRAILING_JUNK:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def is_valid_url(url: str) -> bool:
    """Return True only for well-formed, fetchable http(s) URLs.

    Rejects bare domains such as ``paypal.com`` or ``McKinsey.org`` (no
    scheme => not a URL a browser could navigate to on its own), as well as
    non-web schemes like ``mailto:`` or ``javascript:``.

    Args:
        url: The candidate string to validate.

    Returns:
        True if ``url`` parses as an http/https URL with a network location.
    """
    if not url or not isinstance(url, str):
        return False

    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    # A netloc must contain at least one dot or be a valid host; reject
    # obviously broken values like "https:///path".
    if "." not in parsed.netloc and parsed.netloc.lower() != "localhost":
        return False

    return True


def extract_urls_from_html(html: str, base_url: Optional[str] = None) -> Tuple[List[str], dict]:
    """Extract every hyperlink destination from an HTML document.

    Reads the ``href`` attribute of ``<a>`` tags directly, instead of relying
    on ``get_text()``, which is what caused the "malformed URL" bug: visible
    anchor text (e.g. "McKinsey.org") is not the same thing as the link's
    real destination (e.g. "https://links.mckinsey.com/abc123").

    Args:
        html: Raw HTML content of the email part.
        base_url: Optional base URL to resolve relative hrefs against.

    Returns:
        A tuple of (list of destination URLs, dict mapping URL -> anchor text).
    """
    urls: List[str] = []
    anchor_map: dict = {}

    if not html:
        return urls, anchor_map

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:  # Malformed HTML must never crash the pipeline.
        logger.warning("Failed to parse HTML body: %s", exc)
        return urls, anchor_map

    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if not href:
            continue
        href = href.strip()

        scheme = urlparse(href).scheme.lower()
        if scheme in IGNORED_URL_SCHEMES:
            continue

        if base_url and not scheme:
            try:
                href = urljoin(base_url, href)
            except ValueError:
                continue

        href = _clean_trailing_punctuation(href)
        anchor_text = tag.get_text(strip=True)

        if href not in urls:
            urls.append(href)
        if anchor_text:
            anchor_map[href] = anchor_text

    return urls, anchor_map


def extract_visible_text(html: str) -> str:
    """Return the human-visible text of an HTML email, entities decoded.

    Kept separate from URL extraction on purpose: the visible body is used
    for ML text features and for display, while link destinations come from
    ``extract_urls_from_html`` so the two never get conflated again.
    """
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    except Exception as exc:
        logger.warning("Failed to extract visible text from HTML: %s", exc)
        return ""


def extract_urls_from_text(text: str) -> List[str]:
    """Find bare ``http(s)://`` URLs inside a plain-text string.

    Args:
        text: Plain text (email body, subject, etc.)

    Returns:
        List of URLs found, in order of appearance, without duplicates.
    """
    if not text:
        return []

    found = []
    for match in _PLAIN_TEXT_URL_RE.findall(text):
        cleaned = _clean_trailing_punctuation(match)
        if cleaned and cleaned not in found:
            found.append(cleaned)
    return found


def merge_urls(*url_lists: Iterable[str]) -> List[str]:
    """Merge multiple URL lists, preserving order and removing duplicates."""
    merged: List[str] = []
    for url_list in url_lists:
        for url in url_list:
            if url not in merged:
                merged.append(url)
    return merged


def resolve_final_destination(
    url: str,
    max_redirects: int = 5,
    timeout: float = 5.0,
) -> str:
    """Follow redirects to find a tracking/shortlink's real destination.

    Many legitimate senders (marketing platforms, newsletter tools) wrap
    links in click-tracking redirectors, e.g. ``links.mckinsey.com``. Rather
    than judging the tracking domain, this resolves the chain of redirects
    to the final landing page so reputation checks look at where the link
    actually goes.

    Tries a cheap HEAD request first and only falls back to GET if the
    server doesn't support HEAD (common with some tracking redirectors).
    Redirects are capped to avoid following a redirect loop forever.

    Args:
        url: The URL to resolve.
        max_redirects: Safety cap on the number of hops to follow.
        timeout: Per-request timeout, in seconds.

    Returns:
        The final destination URL, or the original URL if resolution fails
        for any reason (network error, timeout, malformed response, etc).
    """
    if not is_valid_url(url):
        return url

    session = requests.Session()
    session.max_redirects = max_redirects

    try:
        response = session.head(url, allow_redirects=True, timeout=timeout)
        # Some servers respond to HEAD with 405/501; retry with GET in that case.
        if response.status_code in (405, 501):
            response = session.get(url, allow_redirects=True, timeout=timeout, stream=True)
            response.close()
        return response.url or url
    except requests.exceptions.TooManyRedirects:
        logger.warning("Too many redirects while resolving: %s", url)
        return url
    except requests.exceptions.RequestException as exc:
        logger.debug("Could not resolve redirect for %s: %s", url, exc)
        return url
