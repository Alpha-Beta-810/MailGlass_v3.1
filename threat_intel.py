"""
threat_intel.py
----------------
Thin, defensive wrappers around the PhishTank and VirusTotal APIs.

Both functions are designed to never raise: any network error, timeout, or
unexpected response shape is caught and turned into an ``'unknown'`` /
``'error'`` verdict so a single flaky API call can't crash analysis of an
otherwise-fine email.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_USER_AGENT = "phishtank/PhishDet"
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

REQUEST_TIMEOUT_SECONDS = 10


def check_phishtank(url: str) -> str:
    """Query PhishTank for a URL's reputation.

    Args:
        url: A pre-validated http(s) URL.

    Returns:
        One of ``'malicious'``, ``'suspicious'``, or ``'unknown'``.
        Never raises.
    """
    headers = {"User-Agent": PHISHTANK_USER_AGENT}
    payload = {"url": url, "format": "json"}
    if PHISHTANK_API_KEY:
        payload["app_key"] = PHISHTANK_API_KEY

    try:
        response = requests.post(
            PHISHTANK_API_URL, data=payload, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS
        )
    except requests.exceptions.Timeout:
        logger.warning("PhishTank request timed out for %s", url)
        return "unknown"
    except requests.exceptions.RequestException as exc:
        logger.warning("PhishTank request failed for %s: %s", url, exc)
        return "unknown"

    if response.status_code != 200:
        logger.warning("PhishTank returned HTTP %s for %s", response.status_code, url)
        return "unknown"

    try:
        data = response.json()
    except ValueError:
        logger.warning("PhishTank returned a non-JSON response for %s", url)
        return "unknown"

    results = data.get("results", {})
    in_database = results.get("in_database", False)
    verified = results.get("verified", False)
    valid = results.get("valid", False)

    if in_database and verified and valid:
        return "malicious"
    if in_database and not verified:
        return "suspicious"
    return "unknown"


def get_file_sha256(filepath: str) -> Optional[str]:
    """Compute the SHA-256 hash of a file on disk.

    Returns None (instead of raising) if the file can't be read.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except OSError as exc:
        logger.warning("Could not hash attachment %s: %s", filepath, exc)
        return None


def check_virustotal(file_hash: str) -> str:
    """Query VirusTotal for a file hash's reputation.

    Args:
        file_hash: SHA-256 hash of the attachment.

    Returns:
        One of ``'malicious'``, ``'safe'``, or ``'unknown'``. Never raises.
    """
    if not file_hash:
        return "unknown"
    if not VIRUSTOTAL_API_KEY:
        logger.info("VIRUSTOTAL_API_KEY not set; skipping VirusTotal lookup.")
        return "unknown"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_FILE_URL + file_hash

    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.Timeout:
        logger.warning("VirusTotal request timed out for hash %s", file_hash)
        return "unknown"
    except requests.exceptions.RequestException as exc:
        logger.warning("VirusTotal request failed for hash %s: %s", file_hash, exc)
        return "unknown"

    if response.status_code == 404:
        return "unknown"
    if response.status_code != 200:
        logger.warning("VirusTotal returned HTTP %s for hash %s", response.status_code, file_hash)
        return "unknown"

    try:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except (ValueError, KeyError) as exc:
        logger.warning("Unexpected VirusTotal response shape for %s: %s", file_hash, exc)
        return "unknown"

    malicious_count = stats.get("malicious", 0)
    return "malicious" if malicious_count > 0 else "safe"


class ReputationCache:
    """Avoids repeat network calls for URLs seen more than once in an email.

    A single marketing email can repeat the same tracking link a dozen
    times; there's no reason to hit PhishTank once per occurrence.
    """

    def __init__(self) -> None:
        self._url_results: Dict[str, str] = {}

    def get_or_check(self, url: str) -> str:
        if url in self._url_results:
            return self._url_results[url]
        result = check_phishtank(url)
        self._url_results[url] = result
        return result
