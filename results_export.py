"""
results_export.py
-------------------
Persist per-email analysis results to CSV or JSON, so a batch run leaves
behind an artifact you can filter, diff, or feed into another tool -
covering the same need the original ``test_eml_files_clean.py`` served
with ``eml_test_results.csv``, but for the full hybrid verdict (risk score
+ every contributing factor) rather than just the ML label.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import asdict, dataclass, field
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class EmailResult:
    """Summary of one email's analysis, suitable for tabular export."""

    filename: str
    sender: str
    subject: str
    url_count: int = 0
    malicious_urls: int = 0
    suspicious_urls: int = 0
    whitelisted_urls: int = 0
    attachment_count: int = 0
    malicious_attachments: int = 0
    ml_prediction: str = ""
    ml_confidence: float = 0.0
    risk_score: int = 0
    verdict: str = "SAFE"
    risk_label: str = "Very Low"
    confidence: str = "High"
    factors: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)


def to_csv_string(results: List[EmailResult]) -> str:
    """Serialize results to a CSV string; list fields flattened with '; '."""
    if not results:
        return ""
    buffer = io.StringIO()
    fieldnames = list(asdict(results[0]).keys())
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for result in results:
        row = asdict(result)
        # Flatten any list-valued field generically (currently 'factors'
        # and 'parse_errors', but this way a future field addition can't
        # silently break CSV writing).
        for key, value in row.items():
            if isinstance(value, list):
                row[key] = "; ".join(str(v) for v in value)
        writer.writerow(row)
    return buffer.getvalue()


def to_json_string(results: List[EmailResult]) -> str:
    """Serialize results to a JSON string (list of objects)."""
    return json.dumps([asdict(r) for r in results], indent=2)


def write_csv(results: List[EmailResult], path: str) -> None:
    """Write results to a CSV file; list fields are flattened with '; '."""
    if not results:
        logger.info("No results to write to %s", path)
        return
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write(to_csv_string(results))
        print(f"Results written to {path}")
    except OSError as exc:
        logger.warning("Could not write CSV results to %s: %s", path, exc)


def write_json(results: List[EmailResult], path: str) -> None:
    """Write results to a JSON file as a list of objects."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_json_string(results))
        print(f"Results written to {path}")
    except OSError as exc:
        logger.warning("Could not write JSON results to %s: %s", path, exc)
