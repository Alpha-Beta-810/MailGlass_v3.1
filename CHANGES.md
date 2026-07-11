# What changed and why

The workflow is unchanged: `Read .eml → Parse HTML+Text → Extract URLs →
Validate → Whitelist → PhishTank → VirusTotal → ML → Risk Score → Final
Verdict`. `blacklist.py` has been split into focused modules and rewritten
as `phishing_detector.py` (the new entry point — run `python
phishing_detector.py` exactly as you ran `python blacklist.py` before).

| File | Purpose |
|---|---|
| `phishing_detector.py` | Main entry point / orchestrator (replaces `blacklist.py`) |
| `email_utils.py` | `.eml` parsing: subject, sender, body, attachments |
| `url_utils.py` | URL extraction, validation, redirect resolution |
| `whitelist_utils.py` | Domain normalization + root-domain-aware whitelist matching |
| `threat_intel.py` | PhishTank + VirusTotal API calls |
| `risk_engine.py` | Weighted risk scoring and SAFE/SUSPICIOUS/MALICIOUS classification |
| `ml_analysis.py` | ML fallback model + human-readable explanation |
| `model_classes.py`, `whitelist.json`, `phishing_email_model_fixed.pkl` | Unchanged from the original project |

## 1. The href bug (highest priority) — fixed
`url_utils.extract_urls_from_html()` now reads the `href` attribute of every
`<a>`/`<area>` tag directly with BeautifulSoup, instead of extracting URLs
from `soup.get_text()`. The visible anchor text (`extract_visible_text()`)
is now a completely separate value, kept for display/ML use but never fed
to a reputation check. Anchor text is also captured per-URL
(`anchor_map`) so you can flag anchor-vs-destination mismatches later if
you want to.

Verified against the exact example in the brief:
```
<a href="https://links.mckinsey.com/abc123">McKinsey.org</a>
```
now extracts `https://links.mckinsey.com/abc123`, not `McKinsey.org`.

## 2. URL validation — added
`url_utils.is_valid_url()` uses `urlparse()` to require an `http`/`https`
scheme and a network location. Bare domains (`McKinsey.org`, `paypal.com`)
are rejected before ever reaching PhishTank; the "Malformed URL" failure
mode is gone because those strings are simply skipped with a logged
message instead of being queried.

## 3. Better HTML parsing — done
`javascript:`, `mailto:`, `tel:`, `cid:`, and `data:` links are filtered out
in `extract_urls_from_html()`. BeautifulSoup handles HTML entity decoding
automatically. Malformed HTML is caught and logged rather than raising.

## 4. Whitelist improvement — done
`whitelist_utils.get_root_domain()` and `is_subdomain_of_trusted()` compare
registrable root domains (with a small built-in list of common two-label
public suffixes like `co.uk`, `com.au`, so no network call to a public
suffix list is required). `links.mckinsey.com`, `pages.mckinsey.com`, and
`careers.mckinsey.com` all correctly match a trusted `mckinsey.com` entry,
while `mckinsey-login.com` correctly does **not** — the old substring check
would have been fooled by that lookalike.

## 5. Redirect analysis — added (optional)
`url_utils.resolve_final_destination()` tries a `HEAD` request first
(falling back to `GET` only if the server returns 405/501), follows up to
`max_redirects` hops, and returns the final landing URL. It's off by
default (extra network round-trips per link); set `RESOLVE_REDIRECTS=1`
before running to turn it on. Reputation and whitelist checks then run
against the resolved destination.

## 6. PhishTank optimization — done
`phishing_detector.analyze_urls()` de-duplicates URLs, skips invalid ones,
skips whitelisted ones, and a per-email `ReputationCache` means a link
repeated ten times in one marketing email is only checked once. Output
matches the requested format: `Checking → (redirects to) → Whitelisted /
verdict`.

## 7. Final verdict logic — replaced with weighted scoring
`risk_engine.py` implements exactly the scoring scheme requested:

| Signal | Points |
|---|---|
| Known phishing URL | +100 |
| PhishTank "suspicious" (in DB, unverified) | +40 |
| VirusTotal malicious attachment | +100 |
| ML phishing probability | 0–100 (model confidence) |
| Trusted whitelist domain | −40 |
| All links HTTPS | −10 |
| Domain age < 30 days | +20 (hook in place; no WHOIS lookup wired up yet) |

0–30 → SAFE, 31–60 → SUSPICIOUS, 61+ → MALICIOUS. `RiskAssessment.explain()`
prints the score and every contributing factor.

If the ML model itself is unavailable (missing file, incompatible
scikit-learn version — see caveat below) rather than silently defaulting
to SAFE, a couple of cheap heuristic signals (suspicious sender pattern,
urgent subject language) contribute a small amount to the score so obvious
red flags aren't lost.

## 8. ML explanation — added
`ml_analysis.ml_detection_check()` returns an `MLExplanation` with the
label/confidence plus: suspicious-sender-pattern flag, urgent-subject flag,
URL count, sender domain, and (best-effort) the model's top contributing
learned features when the pipeline exposes `feature_importances_`.

## 9. Error handling — hardened throughout
Every stage — file reading, MIME parsing, HTML parsing, URL parsing, both
API calls, model loading/prediction, attachment saving — is wrapped in
narrow `try/except` blocks that log and degrade gracefully instead of
raising. `phishing_detector.run()` also wraps each email in a top-level
`try/except` so one corrupt `.eml` can't stop the batch.

## 10. Code quality — refactored
Split into single-responsibility modules, PEP 8-formatted, full type hints
and docstrings on every public function, no duplicated URL/whitelist logic,
`logging` used instead of ad hoc prints for warnings/errors (user-facing
progress still uses `print`, matching the original CLI-report style),
magic numbers replaced with named constants in `risk_engine.py`.

## Known caveat: scikit-learn version mismatch
The bundled `phishing_email_model_fixed.pkl` was trained with
scikit-learn 1.6.1; if you're on a materially newer scikit-learn some
internal classes (e.g. `_RemainderColsList`) may not unpickle. If you hit
this, either `pip install "scikit-learn==1.6.1"` or retrain with
`python ml_integration_fixed.py` on your current scikit-learn version. This
is an environment/version issue, not a bug in the pipeline logic — the
system already degrades gracefully to the heuristic fallback described in
point 7 when it happens, rather than crashing.

## Try it
```bash
pip install -r requirements.txt
mkdir -p emails         # drop your .eml files here
export VIRUSTOTAL_API_KEY=...   # optional, enables attachment scanning
export PHISHTANK_API_KEY=...    # optional
export RESOLVE_REDIRECTS=1      # optional, follows tracking-link redirects
python phishing_detector.py
```
Two sample `.eml` files are included under `emails/` that exercise the
exact McKinsey href-vs-anchor-text scenario and a `mckinsey-login.com`
lookalike, so you can see the fix in action immediately.

---

# Round 2: pre-submission enhancements

## 11. CSV/score inconsistency — fixed
`RiskAssessment.score` is the raw, unclamped sum of every factor (a
heavily-trusted email can legitimately net to something like -50). The bug:
`phishing_detector.analyze_email()` wrote that raw score straight into
`EmailResult.risk_score`, so the CSV showed `-50` for a SAFE email instead
of the published 0-100 scale — technically not wrong, just confusing (a
negative "risk score" reads like a bug, not "very trusted"). Fixed by
adding `RiskAssessment.clamped_score` (0-100) and using it everywhere a
score is displayed or exported: the CLI's `explain()` output, the CSV/JSON
`risk_score` column, and the web dashboard's gauge. The raw score is still
shown alongside it in `explain()` when it differs, for anyone debugging
the breakdown.

## 12. Domain age not actually scored — fixed
`get_domain_age_days()` was being called and *printed* per-URL in
`analyze_urls()`, but the result was discarded — never passed into
`score_email()`. So "WHOIS-based domain age checking" existed as a visible
side effect with zero influence on the verdict. Fixed: `analyze_urls()`
now returns `(verdicts, domain_ages)`; `analyze_email()` also WHOIS-checks
the sender's own domain (not just link domains), takes the *youngest*
domain found across both, and feeds it into `score_email(domain_age_days=...)`
so a domain registered a few days ago actually adds +20 to the score, as
originally specified.

## 13. Typosquatting detection — added (`typosquat_detection.py`)
New module, deliberately separate from `domain_intel.detect_homograph_risk`
(which only catches Unicode/script-mixing spoofing). This catches
plain-ASCII lookalikes:
- character substitution: `micr0soft.com`, `g00gle.com`, `paypa1.com`
  (Levenshtein distance against a brand's domain label, tolerance scaled to
  label length)
- combosquatting: `mckinsey-login.com`, `paypal-secure-verify.com` (brand
  name + extra word)
- suffix/TLD swap: `mckinsey.net` impersonating `mckinsey.com`

Brand list is a curated shortlist of ~26 commonly-impersonated brands
(Microsoft, Google, Apple, PayPal, banks, McKinsey, etc.) rather than the
full ~300-entry whitelist, to avoid similarity-match noise — with an
optional `whitelist.json` `"typosquatBrands"` key to opt in extra brands
per-project. A domain that's already trusted anywhere in the whitelist is
never flagged. Wired into `risk_engine.score_email()` as
`typosquat_findings` (+45 each), same pattern as `homograph_findings`.
17 new tests in `tests/test_typosquat_detection.py`.

## 14. Explainability — extended for the web UI
`RiskAssessment.reasons()` returns plain-language reasons with no point
values, for a checklist-style "why was this flagged" section (the CLI
`explain()` output keeps showing point values; the web dashboard's detail
page renders each factor as a ✓/⚠ line item).

## 15. ML model unpickling fixed outside the CLI entry point
`model_classes.py` now registers `SenderPatternFeatures` /
`URLFeatureExtractor` onto `sys.modules['__main__']` unconditionally at
import time, instead of relying on `phishing_detector.py` itself being run
as `__main__` (a comment in the old code even said as much). Without this,
importing `phishing_detector.analyze_email()` from anywhere else — like
the new Flask app — silently broke the ML fallback (`joblib` couldn't find
`__main__.SenderPatternFeatures`, and it degraded to the heuristic
fallback instead of running the real model, since the CLI is on a
critical `Exception -> ERROR` catch-all here).

## 16. Flask cybersecurity dashboard — added (`app.py`)
Local single-process web UI wrapping the same `phishing_detector.py`
pipeline used by the CLI:
- Multi-file `.eml` upload (drag-and-drop or file picker), with the same
  `resolve_redirects` / `check_domain_age` options as the CLI flags
- Dashboard: total scanned, SAFE/SUSPICIOUS/MALICIOUS counts, average ML
  confidence, a results table linking to each email's detail page
- Per-email detail page: risk-score gauge, explainable factor breakdown,
  every extracted URL with its verdict *and* its visible anchor text side
  by side (so the original href-vs-anchor-text bug fix is visible in the
  UI itself), attachment VirusTotal verdicts, ML fallback explanation,
  typosquat/homograph findings, and WHOIS domain ages
- CSV/JSON download of the current scan's results

Run with `python app.py`, then open `http://127.0.0.1:5000`. Scope note:
results live in memory for the life of the process (no database) — fine
for local demos/grading, not meant to be deployed as a shared service.

## Try the round-2 features
```bash
python app.py
# open http://127.0.0.1:5000, upload the .eml files in emails/, and check
# "Check domain age" / "Resolve tracking-link redirects" if you want those too
```
Or from the CLI, unchanged:
```bash
python phishing_detector.py --check-domain-age --resolve-redirects
```
