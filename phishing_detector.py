"""
phishing_detector.py
---------------------
Main entry point for the hybrid phishing email detection system.

Pipeline (unchanged from the original design):

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
    Machine Learning
          |
    Risk Score
          |
    Final Verdict

Run with:  python phishing_detector.py
Put .eml files to analyze in an "emails/" directory next to this script.

Configuration is layered defaults -> config.json -> environment variables
-> CLI flags (see config.py). Run `python phishing_detector.py --help` for
all available flags.
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

import config as config_module
import threat_intel
from domain_intel import detect_homograph_risk, get_domain_age_days
from email_utils import ParsedEmail, parse_eml_file
from ml_analysis import ml_detection_check
from typosquat_detection import detect_typosquat

# Importing model_classes registers SenderPatternFeatures/URLFeatureExtractor
# onto sys.modules['__main__'] as a side effect (see the bottom of that
# file), which is what lets joblib unpickle the trained model regardless
# of which module ends up being __main__. Do not remove even though these
# names aren't referenced directly below.
from model_classes import SenderPatternFeatures, URLFeatureExtractor  # noqa: F401
from results_export import EmailResult, write_csv, write_json
from risk_engine import score_email
from threat_intel import ReputationCache, check_virustotal, get_file_sha256
from url_utils import is_valid_url, resolve_final_destination
from whitelist_utils import (
    get_domain_from_url,
    is_sender_whitelisted,
    is_whitelisted,
    load_whitelist,
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define and parse CLI flags (all optional; fall back to config.py defaults)."""
    parser = argparse.ArgumentParser(
        description="Hybrid phishing email detector (blacklist + ML fallback)."
    )
    parser.add_argument("--emails-dir", dest="emails_dir", help="Directory of .eml files to analyze.")
    parser.add_argument("--whitelist-file", dest="whitelist_file", help="Path to whitelist JSON config.")
    parser.add_argument("--model-path", dest="model_path", help="Path to the trained .pkl model.")
    parser.add_argument(
        "--resolve-redirects",
        dest="resolve_redirects",
        action="store_true",
        default=None,
        help="Follow tracking-link redirects to their final destination before checking reputation.",
    )
    parser.add_argument(
        "--check-domain-age",
        dest="check_domain_age",
        action="store_true",
        default=None,
        help="Perform a WHOIS lookup on link domains to flag recently-registered domains (slower, needs network).",
    )
    parser.add_argument("--output-csv", dest="output_csv", help="Write a summary of results to this CSV path.")
    parser.add_argument("--output-json", dest="output_json", help="Write a summary of results to this JSON path.")
    parser.add_argument("--config", dest="config_path", default=config_module.DEFAULT_CONFIG_PATH,
                         help="Path to an optional JSON config file (default: config.json).")
    parser.add_argument("--log-level", dest="log_level", help="Logging level: DEBUG, INFO, WARNING, ERROR.")
    return parser.parse_args()


def analyze_urls(
    urls: List[str],
    whitelist: dict,
    reputation_cache: ReputationCache,
    resolve_redirects: bool,
    check_domain_age: bool,
) -> "tuple[Dict[str, str], Dict[str, int]]":
    """Validate, de-duplicate, whitelist-check, and reputation-check URLs.

    Invalid URLs (bare domains, javascript:/mailto: links, etc.) are logged
    and skipped entirely rather than sent to PhishTank, which fixes the
    original "Malformed URL" failure mode.

    Args:
        urls: Raw candidate URLs extracted from the email.
        whitelist: Loaded whitelist configuration.
        reputation_cache: Shared cache so repeated links only cost one
            PhishTank query.
        resolve_redirects: Whether to follow tracking-link redirects first.
        check_domain_age: Whether to run a WHOIS lookup on each domain.

    Returns:
        A tuple of:
          - Mapping of URL -> verdict, where verdict is one of
            ``'whitelisted'``, ``'malicious'``, ``'suspicious'``, or
            ``'unknown'``. Invalid/skipped URLs are omitted.
          - Mapping of domain -> age in days, for every domain a WHOIS
            lookup succeeded for (only populated when check_domain_age is
            True). This used to be printed and discarded; it's now
            returned so the risk engine can actually score it.
    """
    verdicts: Dict[str, str] = {}
    domain_ages: Dict[str, int] = {}
    seen = set()

    for raw_url in urls:
        if raw_url in seen:
            continue
        seen.add(raw_url)

        if not is_valid_url(raw_url):
            print(f"    Skipping (not a valid http/https URL): {raw_url}")
            continue

        display_url = raw_url
        if resolve_redirects:
            final_url = resolve_final_destination(raw_url)
            if final_url != raw_url:
                print(f"    {raw_url}\n      -> redirects to: {final_url}")
                display_url = final_url

        print(f"    Checking: {display_url}")

        domain = get_domain_from_url(display_url)
        is_suspicious_domain, homograph_reason = detect_homograph_risk(domain)
        if is_suspicious_domain:
            print(f"      Homograph warning: {homograph_reason}")

        if check_domain_age and domain not in domain_ages:
            age_days = get_domain_age_days(domain)
            if age_days is not None:
                print(f"      Domain age: {age_days} day(s)")
                domain_ages[domain] = age_days

        if is_whitelisted(display_url, whitelist):
            print("      Whitelisted - trusted domain, skipping reputation check.")
            verdicts[display_url] = "whitelisted"
            continue

        verdict = reputation_cache.get_or_check(display_url)
        label = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "unknown": "unknown/not listed"}[verdict]
        print(f"      PhishTank verdict: {label}")
        verdicts[display_url] = verdict

    return verdicts, domain_ages


def analyze_attachments(attachments: List[str]) -> Dict[str, str]:
    """Hash and scan every attachment with VirusTotal.

    Args:
        attachments: File paths saved from the email (see
            :func:`email_utils.extract_attachments`).

    Returns:
        Mapping of file path -> verdict (``'malicious'``, ``'safe'``, or
        ``'unknown'``).
    """
    verdicts: Dict[str, str] = {}
    if not attachments:
        print("  No attachments found.")
        return verdicts

    for attachment in attachments:
        file_hash = get_file_sha256(attachment)
        if not file_hash:
            print(f"  Could not hash attachment: {attachment}")
            continue
        verdict = check_virustotal(file_hash)
        verdicts[attachment] = verdict
        label = {"malicious": "MALICIOUS", "safe": "safe", "unknown": "unknown (not in VT database)"}[verdict]
        print(f"  {attachment}: {label}")

    return verdicts


def analyze_email(
    parsed: ParsedEmail,
    whitelist: dict,
    resolve_redirects: bool = False,
    check_domain_age: bool = False,
) -> "tuple[EmailResult, dict]":
    """Run the full hybrid pipeline on a single parsed email, print a report,
    and return a structured summary suitable for CSV/JSON export.

    Returns:
        A tuple of ``(EmailResult, detail)``. ``EmailResult`` is the flat
        summary used for CSV/JSON export. ``detail`` is a richer dict (URL
        verdicts, attachment verdicts, the full RiskAssessment, and the ML
        explanation object) intended for the web dashboard's per-email
        view; CLI usage can ignore it.
    """
    filename = os.path.basename(parsed.filepath)
    print(f"File: {filename}")
    print(f"From: {parsed.sender}")
    print(f"Subject: {parsed.subject}")

    if parsed.parse_errors:
        for err in parsed.parse_errors:
            print(f"  Parse warning: {err}")

    reputation_cache = ReputationCache()

    print("\nURL ANALYSIS:")
    domain_ages: Dict[str, int] = {}
    if not parsed.candidate_urls:
        print("  No URLs found in this email.")
        url_verdicts: Dict[str, str] = {}
    else:
        url_verdicts, domain_ages = analyze_urls(
            parsed.candidate_urls, whitelist, reputation_cache, resolve_redirects, check_domain_age
        )

    print("\nATTACHMENT ANALYSIS:")
    attachment_verdicts = analyze_attachments(parsed.attachments)

    # --- ML fallback: only worth running if the blacklist stage didn't ---
    # --- already find a definitive malicious signal, and something was ---
    # --- inconclusive (an 'unknown' URL, or an unscanned attachment).   ---
    has_definitive_malicious = any(v == "malicious" for v in url_verdicts.values()) or any(
        v == "malicious" for v in attachment_verdicts.values()
    )
    was_inconclusive = any(v == "unknown" for v in url_verdicts.values()) or any(
        v == "unknown" for v in attachment_verdicts.values()
    )

    ml_prediction, ml_confidence = "", 0.0
    ml_top_features: List[str] = []
    ml_unavailable_heuristics = None
    if not has_definitive_malicious and (was_inconclusive or not parsed.candidate_urls):
        print("\nML FALLBACK ANALYSIS:")
        explanation = ml_detection_check(
            sender=parsed.sender,
            subject=parsed.subject,
            body=parsed.visible_text,
            url_count=len(url_verdicts) if url_verdicts else len(parsed.candidate_urls),
        )
        print("  " + explanation.explain().replace("\n", "\n  "))
        if explanation.prediction in ("PHISHING", "LEGITIMATE"):
            ml_prediction, ml_confidence = explanation.prediction, explanation.confidence
            ml_top_features = explanation.top_features
        elif explanation.error:
            # Model couldn't run (missing file, library version mismatch,
            # etc.) - fall back to the cheap sender/subject heuristics
            # instead of silently treating the email as risk-free.
            ml_unavailable_heuristics = {
                "suspicious_sender": explanation.suspicious_sender,
                "urgent_subject": explanation.urgent_subject,
            }

    # --- Homograph + typosquat findings, across every URL domain + sender -
    homograph_findings: List[str] = []
    typosquat_findings: List[str] = []
    checked_domains = {get_domain_from_url(u) for u in url_verdicts}
    if parsed.sender_domain:
        checked_domains.add(parsed.sender_domain)
    for domain in checked_domains:
        is_suspicious, reason = detect_homograph_risk(domain)
        if is_suspicious:
            homograph_findings.append(f"{domain}: {reason}")

        is_typosquat, reason = detect_typosquat(domain, whitelist)
        if is_typosquat:
            typosquat_findings.append(f"{domain}: {reason}")

    if typosquat_findings:
        print("\nTYPOSQUATTING CHECK:")
        for finding in typosquat_findings:
            print(f"  Look-alike domain: {finding}")

    if parsed.header_findings:
        print("\nHEADER ANALYSIS:")
        for finding in parsed.header_findings:
            print(f"  {finding}")

    # Domain age: also check the sender's domain (not just link domains) so
    # a freshly-registered sending domain counts even in a link-free email.
    if check_domain_age and parsed.sender_domain and parsed.sender_domain not in domain_ages:
        sender_age = get_domain_age_days(parsed.sender_domain)
        if sender_age is not None:
            print(f"\nSender domain age: {sender_age} day(s)")
            domain_ages[parsed.sender_domain] = sender_age

    # Score the *youngest* domain found - the single most suspicious data
    # point - rather than an arbitrary one, since younger is more damning.
    youngest_domain_age = min(domain_ages.values()) if domain_ages else None

    # --- Risk scoring ------------------------------------------------------
    any_trusted_domain = is_sender_whitelisted(parsed.sender, whitelist) or any(
        v == "whitelisted" for v in url_verdicts.values()
    )
    all_https = bool(url_verdicts) and all(u.startswith("https://") for u in url_verdicts)

    assessment = score_email(
        url_verdicts=url_verdicts,
        attachment_verdicts=attachment_verdicts,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        any_trusted_domain=any_trusted_domain,
        all_https=all_https,
        domain_age_days=youngest_domain_age,
        ml_unavailable_heuristics=ml_unavailable_heuristics,
        homograph_findings=homograph_findings,
        typosquat_findings=typosquat_findings,
        header_findings=parsed.header_findings,
    )

    print("\nFINAL VERDICT:")
    print("  " + assessment.explain().replace("\n", "\n  "))
    print()

    result = EmailResult(
        filename=filename,
        sender=parsed.sender,
        subject=parsed.subject,
        url_count=len(parsed.candidate_urls),
        malicious_urls=sum(1 for v in url_verdicts.values() if v == "malicious"),
        suspicious_urls=sum(1 for v in url_verdicts.values() if v == "suspicious"),
        whitelisted_urls=sum(1 for v in url_verdicts.values() if v == "whitelisted"),
        attachment_count=len(parsed.attachments),
        malicious_attachments=sum(1 for v in attachment_verdicts.values() if v == "malicious"),
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        risk_score=assessment.clamped_score,
        verdict=assessment.verdict,
        risk_label=assessment.risk_label,
        confidence=assessment.confidence,
        factors=[f.reason for f in assessment.factors],
        parse_errors=parsed.parse_errors,
    )

    detail = {
        "parsed": parsed,
        "url_verdicts": url_verdicts,
        "attachment_verdicts": attachment_verdicts,
        "domain_ages": domain_ages,
        "homograph_findings": homograph_findings,
        "typosquat_findings": typosquat_findings,
        "assessment": assessment,
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "ml_top_features": ml_top_features,
        "header_findings": parsed.header_findings,
    }
    return result, detail


def run(settings: Optional[config_module.Settings] = None) -> List[EmailResult]:
    """Run the hybrid detection pipeline over every .eml file in a directory.

    Args:
        settings: Resolved configuration; if omitted, loads defaults via
            :func:`config.load_settings` with no CLI overrides.

    Returns:
        List of per-email results, in the order files were processed.
    """
    settings = settings or config_module.load_settings()

    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if settings.phishtank_api_key:
        threat_intel.PHISHTANK_API_KEY = settings.phishtank_api_key
    if settings.virustotal_api_key:
        threat_intel.VIRUSTOTAL_API_KEY = settings.virustotal_api_key

    whitelist = load_whitelist(settings.whitelist_file)

    eml_path = Path(settings.emails_dir)
    if not eml_path.exists():
        print(f"Directory '{settings.emails_dir}' does not exist. Create it and add .eml files to analyze.")
        return []

    eml_files = sorted(eml_path.glob("*.eml"))
    if not eml_files:
        print(f"No .eml files found in '{settings.emails_dir}'.")
        return []

    print(f"Found {len(eml_files)} email(s) to analyze.\n")

    results: List[EmailResult] = []
    for eml_file in eml_files:
        print("-" * 70)
        try:
            parsed = parse_eml_file(str(eml_file))
            result, _detail = analyze_email(
                parsed,
                whitelist,
                resolve_redirects=settings.resolve_redirects,
                check_domain_age=settings.check_domain_age,
            )
            results.append(result)
        except Exception as exc:
            # Last-resort safety net: one catastrophically broken email
            # must never stop the batch.
            logger.error("Unexpected error analyzing %s: %s", eml_file, exc)
            print(f"Unexpected error analyzing {eml_file.name}: {exc}\n")

    print("-" * 70)
    print("Analysis complete.")

    if settings.output_csv:
        write_csv(results, settings.output_csv)
    if settings.output_json:
        write_json(results, settings.output_json)

    return results


def main() -> None:
    args = parse_args()
    cli_overrides = {
        "emails_dir": args.emails_dir,
        "whitelist_file": args.whitelist_file,
        "model_path": args.model_path,
        "resolve_redirects": args.resolve_redirects,
        "check_domain_age": args.check_domain_age,
        "output_csv": args.output_csv,
        "output_json": args.output_json,
        "log_level": args.log_level,
    }
    settings = config_module.load_settings(config_path=args.config_path, cli_overrides=cli_overrides)
    run(settings)


if __name__ == "__main__":
    main()
