"""
history_store.py
-----------------
Persistent, cross-run scan history for the web dashboard.

Problem this solves: app.py's ``RUNS`` dict only lives in the Flask
process's memory. Every new /analyze POST got its own fresh ``run_id``,
and there was no view that showed anything from a previous run once you
navigated away from it - and restarting the server (or a code reload)
wiped everything. Scanning a second batch of emails didn't actually
delete the first batch's data, but there was no way to find it again.

This module persists every individual scanned email to a small SQLite
database file on disk (``scan_history.db`` by default), so:
  - a `/history` page can list every email ever scanned, oldest run or
    newest, across the whole lifetime of the app - not just the current
    one;
  - `/dashboard/<run_id>` and `/email/<run_id>/<filename>` keep working
    even after a server restart, by reconstructing the same
    EmailResult / ParsedEmail / RiskAssessment objects the templates
    already know how to render;
  - nothing here changes the scoring/analysis logic at all - it's a
    storage layer bolted onto the existing in-memory RUNS dict, not a
    replacement for it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple

from email_utils import ParsedEmail
from results_export import EmailResult
from risk_engine import RiskAssessment, RiskFactor

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "scan_history.db"


@contextmanager
def _connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create the history tables if they don't already exist. Safe to call every startup."""
    with _connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                resolve_redirects INTEGER NOT NULL DEFAULT 0,
                check_domain_age INTEGER NOT NULL DEFAULT 0,
                skipped INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                result_json TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                UNIQUE(run_id, filename)
            )
            """
        )


def save_run_meta(
    db_path: str,
    run_id: str,
    created_at: str,
    resolve_redirects: bool,
    check_domain_age: bool,
    skipped: int,
) -> None:
    """Record the per-run toggles once, alongside the per-email scan rows."""
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO runs (run_id, created_at, resolve_redirects, check_domain_age, skipped)
            VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, created_at, int(resolve_redirects), int(check_domain_age), skipped),
        )


def _serialize_detail(detail: dict) -> dict:
    """Turn a ``detail`` dict (as built by phishing_detector.analyze_email)
    into something json.dumps can handle, without losing any information
    needed to reconstruct it later.
    """
    data = dict(detail)

    parsed = data.get("parsed")
    if parsed is not None:
        data["parsed"] = asdict(parsed)

    assessment = data.get("assessment")
    if assessment is not None:
        data["assessment"] = {
            "score": assessment.score,
            "factors": [asdict(f) for f in assessment.factors],
            "has_unknown_signal": assessment.has_unknown_signal,
            "ml_ran": assessment.ml_ran,
            "ml_unavailable": assessment.ml_unavailable,
        }

    return data


def _deserialize_detail(data: dict) -> dict:
    """Inverse of :func:`_serialize_detail` - rebuilds real ParsedEmail /
    RiskAssessment objects so detail.html's ``assessment.explain()`` /
    ``.verdict`` / ``.risk_label`` / ``.confidence`` properties all work
    exactly the same as they would for an in-memory (never-restarted) run.
    """
    data = dict(data)

    parsed = data.get("parsed")
    if parsed is not None:
        data["parsed"] = ParsedEmail(**parsed)

    assessment = data.get("assessment")
    if assessment is not None:
        data["assessment"] = RiskAssessment(
            score=assessment.get("score", 0),
            factors=[RiskFactor(**f) for f in assessment.get("factors", [])],
            has_unknown_signal=assessment.get("has_unknown_signal", False),
            ml_ran=assessment.get("ml_ran", False),
            ml_unavailable=assessment.get("ml_unavailable", False),
        )

    return data


def save_scan(
    db_path: str,
    run_id: str,
    filename: str,
    scanned_at: str,
    result: EmailResult,
    detail: dict,
) -> None:
    """Persist one email's analysis. Never raises - a storage hiccup
    shouldn't break the scan the user is actively waiting on; it just
    means that one entry won't show up in /history later.
    """
    try:
        result_json = json.dumps(asdict(result))
        detail_json = json.dumps(_serialize_detail(detail))
    except (TypeError, ValueError) as exc:
        logger.warning("Could not serialize scan result for history (%s): %s", filename, exc)
        return

    try:
        with _connect(db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (run_id, filename, scanned_at, result_json, detail_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, filename, scanned_at, result_json, detail_json),
            )
    except sqlite3.Error as exc:
        logger.warning("Could not write scan history for %s: %s", filename, exc)


def _row_to_result_detail(row: sqlite3.Row) -> Tuple[EmailResult, dict]:
    result = EmailResult(**json.loads(row["result_json"]))
    detail = _deserialize_detail(json.loads(row["detail_json"]))
    return result, detail


def get_run(db_path: str, run_id: str) -> Optional[dict]:
    """Reconstruct one run's worth of results/details from disk.

    Returns a dict shaped like app.py's in-memory ``RUNS[run_id]`` entry,
    or None if this run_id has no persisted scans at all.
    """
    with _connect(db_path) as conn:
        meta_row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        scan_rows = conn.execute(
            "SELECT * FROM scans WHERE run_id = ? ORDER BY id ASC", (run_id,)
        ).fetchall()

    if not scan_rows:
        return None

    results: List[EmailResult] = []
    details: Dict[str, dict] = {}
    for row in scan_rows:
        result, detail = _row_to_result_detail(row)
        results.append(result)
        details[row["filename"]] = detail

    return {
        "results": results,
        "details": details,
        "resolve_redirects": bool(meta_row["resolve_redirects"]) if meta_row else False,
        "check_domain_age": bool(meta_row["check_domain_age"]) if meta_row else False,
        "skipped": meta_row["skipped"] if meta_row else 0,
    }


def get_scan(db_path: str, run_id: str, filename: str) -> Optional[Tuple[EmailResult, dict]]:
    """Reconstruct a single persisted scan, for the detail page fallback."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE run_id = ? AND filename = ?", (run_id, filename)
        ).fetchone()
    if row is None:
        return None
    return _row_to_result_detail(row)


def get_all_scans(db_path: str, limit: Optional[int] = None) -> List[dict]:
    """Every scan ever recorded, newest first, for the /history page.

    Returns a list of dicts: ``{run_id, filename, scanned_at, result}``.
    Deliberately doesn't reconstruct the (heavier) detail blob here - the
    history table only needs the flat EmailResult summary; the detail
    page re-fetches its own row on demand via :func:`get_scan`.
    """
    query = "SELECT run_id, filename, scanned_at, result_json FROM scans ORDER BY id DESC"
    if limit:
        query += f" LIMIT {int(limit)}"
    with _connect(db_path) as conn:
        rows = conn.execute(query).fetchall()

    scans = []
    for row in rows:
        try:
            result = EmailResult(**json.loads(row["result_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Skipping unreadable history row for %s: %s", row["filename"], exc)
            continue
        scans.append(
            {
                "run_id": row["run_id"],
                "filename": row["filename"],
                "scanned_at": row["scanned_at"],
                "result": result,
            }
        )
    return scans


def clear_history(db_path: str) -> None:
    """Wipe every persisted scan and run record. Used by the "Clear history" action."""
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM scans")
        conn.execute("DELETE FROM runs")
