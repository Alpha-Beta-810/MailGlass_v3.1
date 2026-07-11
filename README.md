# 🔍MailGlass_v3.1: A Hybrid Phishing Email Detection System

MailGlass is a hybrid phishing email detector that combines **blacklist-based checks**
(whitelist, PhishTank, VirusTotal) with an **ML fallback classifier**,
plus supporting domain intelligence (WHOIS domain age, IDN/homograph and
typosquat detection) and a weighted, explainable risk score. Usable from
the command line or through a Flask web dashboard.

## 🚀 What's New in Version 3.1

Version **3.1** builds upon the existing hybrid phishing detection platform by introducing **persistent scan history** using SQLite. Scan results are now preserved across application restarts, allowing users to revisit previous analyses, export historical reports, and manage scan history directly from the web interface.

| Feature | Version 3.0 | Version 3.1 |
|:--------|:-----------:|:-----------:|
| Flask Dashboard | ✅ | ✅ |
| Machine Learning Detection | ✅ | ✅ |
| Typosquatting Detection | ✅ | ✅ |
| Email Header Analysis | ✅ | ✅ |
| WHOIS / Domain Intelligence | ✅ | ✅ |
| Explainable Risk Engine | ✅ | ✅ |
| CSV Export | ✅ | ✅ |
| JSON Export | ✅ | ✅ |
| **Persistent SQLite Scan History** | ❌ | ✅ |
| **History Dashboard** | ❌ | ✅ |
| **Dashboard Reconstruction After Server Restart** | ❌ | ✅ |
| **Export Previous Scan Results** | ❌ | ✅ |
| **Clear Scan History** | ❌ | ✅ |

### ✨ New Features in v3.1

- 🗄️ **Persistent SQLite History**
  - Every scan is automatically stored in a local SQLite database (`scan_history.db`).
  - Scan results remain available even after closing or restarting the application.

- 📜 **History Dashboard**
  - View all previously scanned emails.
  - Filter and revisit historical scan results.

- 🔄 **Dashboard Reconstruction**
  - Previously generated dashboards can be reconstructed directly from the database after application restart.

- 📥 **Historical Report Export**
  - Export any previous scan as **CSV** or **JSON** without rescanning the email.

- 🧹 **Clear History**
  - Remove all stored scan history from the application with a single click.

> **Note:** Version 3.1 is fully backward compatible with Version 3.0 while introducing persistent storage and historical analysis capabilities.

## Architecture

```
Read .eml
    |
Parse HTML + Text
    |
Extract href URLs + Plain URLs
    |
Validate URLs
    |
Whitelist
    |
PhishTank
    |
VirusTotal
    |
Machine Learning (only if blacklist stage was inconclusive)
    |
Risk Score
    |
Final Verdict: SAFE / SUSPICIOUS / MALICIOUS
```

## Project layout

| File | Purpose |
|---|---|
| `phishing_detector.py` | **Main entry point.** CLI, orchestration, per-email reporting. |
| `config.py` | Layered settings: defaults -> `config.json` -> env vars -> CLI flags. |
| `email_utils.py` | `.eml` parsing: subject, sender, body, attachments. |
| `url_utils.py` | URL extraction (href-based, not anchor-text), validation, redirect resolution. |
| `whitelist_utils.py` | Domain normalization + root-domain-aware whitelist matching. |
| `threat_intel.py` | PhishTank + VirusTotal API calls, with per-run caching. |
| `domain_intel.py` | WHOIS domain-age lookup + IDN/punycode homograph detection. |
| `typosquat_detection.py` | Look-alike brand domain detection (character substitution, combosquatting, suffix swap). |
| `risk_engine.py` | Weighted risk scoring and SAFE/SUSPICIOUS/MALICIOUS classification. |
| `ml_analysis.py` | ML fallback model + human-readable explanation of its reasoning. |
| `results_export.py` | CSV/JSON export of per-email results. |
| `history_store.py` | Persistent SQLite scan history (survives restarts) backing the web dashboard's History page. |
| `app.py` | Flask web dashboard: upload `.eml` files, browse results in the browser. |
| `templates/`, `static/` | Web dashboard HTML/CSS. |
| `model_classes.py` | Custom sklearn transformers used by the trained pipeline. |
| `ml_integration_fixed.py` | Trains `phishing_email_model_fixed.pkl` from `CEAS_08.csv`. |
| `model_evaluation.py` | Cross-validation, ROC curve, confusion matrix for the trained model. |
| `whitelist.json` | Trusted domains/URLs configuration. |
| `tests/` | Pytest suite covering URL/whitelist/risk/domain-intel logic. |

See `CHANGES.md` for a detailed history of what was fixed/added and why.

## Setup

```bash
pip install -r requirements.txt          # runtime
# or, to also run the test suite:
pip install -r requirements-dev.txt
```

If you hit a scikit-learn version mismatch loading the bundled model (see
**Known caveat** below), either pin `scikit-learn==1.6.1` or retrain the
model under your current scikit-learn version (see **Training**).

## Web dashboard

```bash
python app.py
```

Then open `http://127.0.0.1:5000`. Upload one or more `.eml` files (the
two in `emails/` work as a demo), optionally check "Resolve tracking-link
redirects" / "Check domain age", and you get:

- a dashboard with total scanned + SAFE/SUSPICIOUS/MALICIOUS counts +
  average ML confidence
- a per-email report: risk-score gauge, an explainable factor-by-factor
  breakdown, every extracted URL next to its *visible anchor text* (so you
  can see the href-vs-anchor-text fix in action), attachment scan results,
  the ML fallback's reasoning, and any typosquat/homograph/domain-age
  findings
- CSV/JSON export of the current scan

Every individual scan is also written to a small SQLite database
(`scan_history.db`, created automatically next to `app.py`). A **History**
link in the top nav lists every email ever scanned - across separate
scan batches, and even across restarting the server - with its own
CSV/JSON export and a "Clear history" action. This is what makes
`/dashboard/<run_id>` and `/email/<run_id>/<filename>` links keep working
after a restart too: they fall back to the database if the in-memory
copy is gone. See `history_store.py` for details.

This is a local single-process tool (no user accounts, no auth) - suited
to demos and grading, not to being deployed as a shared internet-facing
service.

## Running detection (CLI)

```bash
mkdir -p emails            # drop your .eml files here
python phishing_detector.py
```

Two sample `.eml` files ship in `emails/` demonstrating the original
href-vs-anchor-text bug fix and a `mckinsey-login.com` lookalike domain.

### CLI flags

```bash
python phishing_detector.py --help
```

| Flag | Effect |
|---|---|
| `--emails-dir DIR` | Directory of `.eml` files (default: `emails`) |
| `--whitelist-file PATH` | Path to whitelist JSON (default: `whitelist.json`) |
| `--model-path PATH` | Path to the trained `.pkl` model |
| `--resolve-redirects` | Follow tracking-link redirects to their final destination before checking reputation |
| `--check-domain-age` | WHOIS-lookup link/sender domains and flag ones registered <30 days ago (slower, needs network + `python-whois`) |
| `--output-csv PATH` | Write a summary of results to CSV |
| `--output-json PATH` | Write a summary of results to JSON |
| `--config PATH` | Path to a JSON config file (default: `config.json`) |
| `--log-level LEVEL` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

### Configuration precedence

`config.py` resolves settings in this order (later wins):
**built-in defaults → `config.json` (if present) → environment variables →
CLI flags.** Copy `config.example.json` to `config.json` to customize
without touching environment variables or flags:

```bash
cp config.example.json config.json
```

Relevant environment variables: `PHISHTANK_API_KEY`, `VIRUSTOTAL_API_KEY`,
`EMAILS_DIR`, `WHITELIST_FILE`, `MODEL_PATH`, `RESOLVE_REDIRECTS`,
`CHECK_DOMAIN_AGE`, `OUTPUT_CSV`, `OUTPUT_JSON`, `LOG_LEVEL`.

### Example: full run with exports and domain-age checks

```bash
export VIRUSTOTAL_API_KEY=your_key_here
python phishing_detector.py --check-domain-age --resolve-redirects \
    --output-csv results.csv --output-json results.json
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

The suite covers: the href-vs-anchor-text extraction fix, URL validation
edge cases, root-domain whitelist matching (including the
`mckinsey-login.com` lookalike case), weighted risk scoring across every
signal, IDN/punycode homograph detection, and typosquat/combosquat/
suffix-swap brand impersonation detection.

## Training the ML model

The trainer expects `CEAS_08.csv` (not included here - it's ~65MB; pull it
from your original dataset export) in the project root.

```bash
python ml_integration_fixed.py
```

This trains a Random Forest pipeline (sender pattern features + TF-IDF on
subject/body + URL count) and writes `phishing_email_model_fixed.pkl`.
Train under the same scikit-learn version you'll run `phishing_detector.py`
with, to avoid the pickle-compatibility issue below.

To evaluate the trained model (confusion matrix, ROC curve, cross-validation):

```bash
python model_evaluation.py
```

## Known caveat: scikit-learn version mismatch

The bundled `.pkl` was trained with scikit-learn 1.6.1. On a materially
newer scikit-learn, some internal classes (e.g. `_RemainderColsList`) may
not unpickle. This is an environment/version issue, not a bug in the
detection logic - the system already degrades gracefully, falling back to
lightweight sender/subject heuristics instead of crashing or silently
reporting SAFE (see `risk_engine.py`'s `ml_unavailable_heuristics` path).
Fix by pinning `scikit-learn==1.6.1`, or retraining per above.

## Extending

- **Trusted domains**: add root domains to `domainsInSubdomains` in `whitelist.json`.
- **Typosquat brand list**: the curated shortlist lives in `typosquat_detection.CURATED_BRANDS`; add project-specific brands to watch via a `"typosquatBrands"` array in `whitelist.json` instead of editing the code.
- **Risk weights**: all point values are named constants at the top of `risk_engine.py`.
- **New signals**: add a field to `results_export.EmailResult`, compute it in `phishing_detector.analyze_email()`, and feed it into `risk_engine.score_email()`.
