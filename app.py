"""
app.py
------
Flask cybersecurity dashboard for the hybrid phishing detector.

Upload one or more .eml files, get a scored SAFE / SUSPICIOUS / MALICIOUS
verdict per email with a full explanation (URL reputation, attachment
scan, ML fallback, homograph/typosquat findings, risk-score breakdown),
plus aggregate stats and CSV/JSON export - the same engine used by
phishing_detector.py's CLI, wrapped in a browser UI for demos.

Run with:  python app.py
Then open: http://127.0.0.1:5000

Note on storage: results for the *current* process live in memory
(`RUNS`, keyed by a random run id) for fast access while the server is
up. Every individual scan is also persisted to a small SQLite database
(`scan_history.db`, see history_store.py) so a `/history` page can list
every email ever scanned - across runs, and even across server restarts
- and `/dashboard/<run_id>` / `/email/<run_id>/<filename>` fall back to
that database if the in-memory copy isn't there anymore. This is still a
single-process local demo tool, not a multi-user production service -
there's no auth, and the SQLite file is shared by whoever runs this on
the same machine.
"""

from __future__ import annotations

import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.utils import secure_filename

import config as config_module
import history_store
import threat_intel
from email_utils import parse_eml_file
from phishing_detector import analyze_email
from results_export import EmailResult, to_csv_string, to_json_string
from whitelist_utils import load_whitelist

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24).hex())

UPLOAD_ROOT = os.path.join(tempfile.gettempdir(), "phishdetect_console_uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# SQLite history file, next to this script (not the OS temp dir) so it
# survives across server restarts the same way whitelist.json does.
HISTORY_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.db")
history_store.init_db(HISTORY_DB_PATH)

SETTINGS = config_module.load_settings()
if SETTINGS.phishtank_api_key:
    threat_intel.PHISHTANK_API_KEY = SETTINGS.phishtank_api_key
if SETTINGS.virustotal_api_key:
    threat_intel.VIRUSTOTAL_API_KEY = SETTINGS.virustotal_api_key

# In-memory store of completed scans, for fast access within this process's
# lifetime. See module docstring: history_store.py is the durable copy.
RUNS: Dict[str, dict] = {}


def _compute_stats(results: List[EmailResult]) -> dict:
    """Aggregate counts/averages for the dashboard summary cards."""
    total = len(results)
    safe = sum(1 for r in results if r.verdict == "SAFE")
    suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    malicious = sum(1 for r in results if r.verdict == "MALICIOUS")
    scored_ml = [r.ml_confidence for r in results if r.ml_prediction in ("PHISHING", "LEGITIMATE")]
    avg_ml_confidence = round(sum(scored_ml) / len(scored_ml), 1) if scored_ml else None
    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious,
        "avg_ml_confidence": avg_ml_confidence,
    }


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze() -> Response:
    files = [f for f in request.files.getlist("eml_files") if f.filename]
    if not files:
        flash("Choose at least one .eml file to scan.", "error")
        return redirect(url_for("index"))

    resolve_redirects = request.form.get("resolve_redirects") == "on"
    check_domain_age = request.form.get("check_domain_age") == "on"

    whitelist = load_whitelist(SETTINGS.whitelist_file)

    run_id = uuid.uuid4().hex[:10]
    run_dir = os.path.join(UPLOAD_ROOT, run_id)
    os.makedirs(run_dir, exist_ok=True)

    results: List[EmailResult] = []
    details: Dict[str, dict] = {}
    skipped = 0
    created = datetime.now(timezone.utc)

    for uploaded in files:
        original_name = uploaded.filename
        if not original_name.lower().endswith(".eml"):
            skipped += 1
            continue

        filename = secure_filename(original_name) or f"upload_{len(results)}.eml"
        # Guard against multiple uploads sharing a sanitized filename.
        base_name, ext = os.path.splitext(filename)
        candidate = filename
        counter = 1
        while candidate in details:
            candidate = f"{base_name}_{counter}{ext}"
            counter += 1
        filename = candidate

        save_path = os.path.join(run_dir, filename)
        uploaded.save(save_path)

        try:
            parsed = parse_eml_file(save_path)
            result, detail = analyze_email(
                parsed, whitelist, resolve_redirects=resolve_redirects, check_domain_age=check_domain_age
            )
            result.filename = filename
        except Exception as exc:
            logger.exception("Failed to analyze %s", filename)
            result = EmailResult(
                filename=filename,
                sender="",
                subject="(failed to parse)",
                verdict="SAFE",
                parse_errors=[f"Analysis failed: {exc}"],
            )
            detail = {}

        results.append(result)
        details[filename] = detail
        history_store.save_scan(
            HISTORY_DB_PATH, run_id, filename, datetime.now(timezone.utc).isoformat(), result, detail
        )

    if not results:
        flash(f"No .eml files found among the {skipped} file(s) uploaded.", "error")
        return redirect(url_for("index"))

    RUNS[run_id] = {
        "results": results,
        "details": details,
        "created": created,
        "resolve_redirects": resolve_redirects,
        "check_domain_age": check_domain_age,
        "skipped": skipped,
    }
    history_store.save_run_meta(
        HISTORY_DB_PATH, run_id, created.isoformat(), resolve_redirects, check_domain_age, skipped
    )
    return redirect(url_for("dashboard", run_id=run_id))


@app.route("/dashboard/<run_id>")
def dashboard(run_id: str) -> str:
    run = RUNS.get(run_id) or history_store.get_run(HISTORY_DB_PATH, run_id)
    if run is None:
        abort(404)
    stats = _compute_stats(run["results"])
    return render_template(
        "dashboard.html",
        run_id=run_id,
        results=run["results"],
        stats=stats,
        skipped=run["skipped"],
        resolve_redirects=run["resolve_redirects"],
        check_domain_age=run["check_domain_age"],
    )


@app.route("/email/<run_id>/<path:filename>")
def email_detail(run_id: str, filename: str) -> str:
    run = RUNS.get(run_id)
    if run is not None:
        result = next((r for r in run["results"] if r.filename == filename), None)
        detail = run["details"].get(filename, {}) if result is not None else None
    else:
        result, detail = None, None

    if result is None:
        persisted = history_store.get_scan(HISTORY_DB_PATH, run_id, filename)
        if persisted is None:
            abort(404)
        result, detail = persisted

    assessment = detail.get("assessment")
    return render_template(
        "detail.html",
        run_id=run_id,
        result=result,
        detail=detail,
        assessment=assessment,
    )


@app.route("/download/<run_id>/<fmt>")
def download(run_id: str, fmt: str) -> Response:
    run = RUNS.get(run_id) or history_store.get_run(HISTORY_DB_PATH, run_id)
    if run is None:
        abort(404)
    results = run["results"]

    if fmt == "csv":
        body = to_csv_string(results)
        return Response(
            body,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=phishing_report_{run_id}.csv"},
        )
    if fmt == "json":
        body = to_json_string(results)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=phishing_report_{run_id}.json"},
        )
    abort(404)


@app.route("/history")
def history() -> str:
    """Every email ever scanned by this app, newest first - across every
    run and every server restart, since it reads straight from the
    persisted SQLite history rather than the in-memory RUNS dict.
    """
    scans = history_store.get_all_scans(HISTORY_DB_PATH)
    stats = _compute_stats([s["result"] for s in scans])
    return render_template("history.html", scans=scans, stats=stats)


@app.route("/history/download/<fmt>")
def history_download(fmt: str) -> Response:
    scans = history_store.get_all_scans(HISTORY_DB_PATH)
    results = [s["result"] for s in scans]

    if fmt == "csv":
        body = to_csv_string(results)
        return Response(
            body,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=phishing_history.csv"},
        )
    if fmt == "json":
        body = to_json_string(results)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=phishing_history.json"},
        )
    abort(404)


@app.route("/history/clear", methods=["POST"])
def history_clear() -> Response:
    history_store.clear_history(HISTORY_DB_PATH)
    flash("Scan history cleared.", "info")
    return redirect(url_for("history"))


@app.errorhandler(404)
def not_found(_exc) -> "tuple[str, int]":
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, host="127.0.0.1", port=5000)
