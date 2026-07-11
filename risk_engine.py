"""
risk_engine.py
--------------
Weighted risk scoring for the final verdict.

Replaces the previous "any malicious signal => MALICIOUS, otherwise ask the
ML model" binary logic with a scored, explainable model: every signal (a
known-bad URL, a malicious attachment, the ML model's phishing probability,
trust signals like a whitelisted domain or HTTPS) contributes points, and
the total determines SAFE / SUSPICIOUS / MALICIOUS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


# --- Scoring weights -------------------------------------------------------
# Centralized here (rather than scattered as magic numbers) so they're easy
# to tune without hunting through the pipeline code.
POINTS_KNOWN_PHISHING_URL = 100
POINTS_SUSPICIOUS_URL = 40
POINTS_MALICIOUS_ATTACHMENT = 100
POINTS_TRUSTED_DOMAIN = -40
POINTS_ALL_HTTPS = -10
POINTS_DOMAIN_AGE_UNDER_30_DAYS = 20

# Lightweight fallback signals, only applied when the ML model itself could
# not be used (e.g. missing model file, library version mismatch) so an
# email with obvious red flags doesn't default to a bare "SAFE" just
# because the classifier was unavailable.
POINTS_HEURISTIC_SUSPICIOUS_SENDER = 15
POINTS_HEURISTIC_URGENT_SUBJECT = 15
POINTS_HOMOGRAPH_DOMAIN = 50
POINTS_TYPOSQUAT_DOMAIN = 45

# Email header red flags (Reply-To/Return-Path domain mismatches, failed
# SPF/DKIM/DMARC). Each finding string from email_utils already says which
# check failed, so one shared weight is applied per finding.
POINTS_HEADER_FINDING = 20

VERDICT_THRESHOLDS = (
    (30, "SAFE"),
    (60, "SUSPICIOUS"),
    (100, "MALICIOUS"),
)


@dataclass
class RiskFactor:
    """A single scored contribution to the overall verdict."""

    points: int
    reason: str


@dataclass
class RiskAssessment:
    """The complete, explainable result of the scoring pass."""

    score: int = 0
    factors: List[RiskFactor] = field(default_factory=list)

    # Confidence tracks a *different* question from the score: not "how
    # dangerous does this look" but "how much solid evidence do we actually
    # have". An email with an unresolved 'unknown' URL and no working ML
    # model can still land on SAFE, but that SAFE means something weaker
    # than one where every signal came back clean and conclusive.
    has_unknown_signal: bool = False
    ml_ran: bool = False
    ml_unavailable: bool = False

    def add(self, points: int, reason: str) -> None:
        if points == 0:
            return
        self.factors.append(RiskFactor(points=points, reason=reason))
        self.score += points

    @property
    def clamped_score(self) -> int:
        """The score clamped to the published 0-100 range.

        ``score`` itself is the raw, unclamped sum of every factor (useful
        internally and for debugging - e.g. seeing that a heavily-trusted
        email landed at -50 rather than merely 0). Anything shown to a user
        or written to a report (CSV/JSON, the CLI summary, the verdict
        classification) must use this clamped value instead, or a SAFE
        email showing a "-50" risk score reads as a bug rather than as
        "very trusted": the negative number has no meaning outside the
        raw factor breakdown.
        """
        return max(0, min(self.score, 100))

    @property
    def verdict(self) -> str:
        """Classify the accumulated score into SAFE / SUSPICIOUS / MALICIOUS."""
        clamped = self.clamped_score
        for ceiling, label in VERDICT_THRESHOLDS:
            if clamped <= ceiling:
                return label
        return "MALICIOUS"

    @property
    def risk_label(self) -> str:
        """A finer-grained qualitative label than the 3-way verdict.

        Lets a SAFE email at score 0 read as "Very Low" risk rather than a
        bare "0/100", which otherwise reads oddly next to a positive score
        showing "SAFE - 12/100" too.
        """
        clamped = self.clamped_score
        if clamped == 0:
            return "Very Low"
        if clamped <= 15:
            return "Low"
        if clamped <= 30:
            return "Elevated"
        if clamped <= 60:
            return "High"
        return "Critical"

    @property
    def confidence(self) -> str:
        """How much solid evidence backs the verdict: High / Medium / Low.

        Separate from the risk score/verdict itself - a low-risk verdict
        reached despite an unresolved 'unknown' URL or a broken ML model is
        real but less certain than one where every check came back clean.
        """
        if self.ml_unavailable and self.has_unknown_signal:
            return "Low"
        if self.ml_unavailable or self.has_unknown_signal:
            return "Medium"
        return "High"

    def reasons(self) -> List[str]:
        """Plain-language reasons only (no point values) for a checklist-style UI."""
        return [factor.reason for factor in self.factors]

    def explain(self) -> str:
        """Render a human-readable breakdown of the score."""
        lines = [
            f"Risk score: {self.clamped_score}/100 -> {self.verdict} ({self.risk_label} risk)",
            f"Confidence: {self.confidence}",
        ]
        if not self.factors:
            lines.append("  (no risk factors triggered)")
        for factor in self.factors:
            sign = "+" if factor.points >= 0 else ""
            lines.append(f"  {sign}{factor.points:>4}  {factor.reason}")
        if self.score != self.clamped_score:
            lines.append(f"  (raw unclamped score: {self.score}, clamped to 0-100 for display/verdict)")
        return "\n".join(lines)


def score_email(
    url_verdicts: dict,
    attachment_verdicts: dict,
    ml_prediction: str = "",
    ml_confidence: float = 0.0,
    any_trusted_domain: bool = False,
    all_https: bool = False,
    domain_age_days: "int | None" = None,
    ml_unavailable_heuristics: "dict | None" = None,
    homograph_findings: "list[str] | None" = None,
    typosquat_findings: "list[str] | None" = None,
    header_findings: "list[str] | None" = None,
) -> RiskAssessment:
    """Compute a weighted risk assessment for one email.

    Args:
        url_verdicts: Mapping of URL -> reputation verdict, one of
            ``'malicious'``, ``'suspicious'``, ``'unknown'``, or
            ``'whitelisted'``.
        attachment_verdicts: Mapping of file path -> VirusTotal verdict
            (``'malicious'``, ``'safe'``, or ``'unknown'``).
        ml_prediction: ``'PHISHING'`` or ``'LEGITIMATE'`` from the ML
            fallback, or ``''`` if the ML step didn't run.
        ml_confidence: Model confidence, 0-100, paired with ml_prediction.
        any_trusted_domain: True if the sender or any URL is whitelisted.
        all_https: True if every extracted URL uses HTTPS.
        domain_age_days: Age of the sending/link domain in days, if known
            (reserved for a future WHOIS-based feature).
        ml_unavailable_heuristics: Only passed when the ML model could not
            run; a dict with ``suspicious_sender`` / ``urgent_subject``
            booleans used as a light substitute so obvious red flags still
            move the score even without a model verdict.
        homograph_findings: List of human-readable reasons from
            :func:`domain_intel.detect_homograph_risk`, one per flagged
            domain (punycode or mixed-script lookalikes).
        typosquat_findings: List of human-readable reasons from
            :func:`typosquat_detection.detect_typosquat`, one per flagged
            domain (character-substitution/combosquat/suffix-swap
            lookalikes of a known brand).
        header_findings: List of human-readable reasons from
            :func:`email_utils`'s header analysis - Reply-To/Return-Path
            domain mismatches and failed SPF/DKIM/DMARC checks.

    Returns:
        A populated RiskAssessment with score, verdict, and explanation.
    """
    assessment = RiskAssessment()

    assessment.has_unknown_signal = any(v == "unknown" for v in url_verdicts.values()) or any(
        v == "unknown" for v in attachment_verdicts.values()
    )
    assessment.ml_ran = ml_prediction in ("PHISHING", "LEGITIMATE")
    assessment.ml_unavailable = bool(ml_unavailable_heuristics)

    malicious_urls = [u for u, v in url_verdicts.items() if v == "malicious"]
    suspicious_urls = [u for u, v in url_verdicts.items() if v == "suspicious"]

    for url in malicious_urls:
        assessment.add(POINTS_KNOWN_PHISHING_URL, f"Known phishing URL: {url}")
    for url in suspicious_urls:
        assessment.add(POINTS_SUSPICIOUS_URL, f"Suspicious/unverified URL flagged by PhishTank: {url}")

    malicious_attachments = [f for f, v in attachment_verdicts.items() if v == "malicious"]
    for attachment in malicious_attachments:
        assessment.add(POINTS_MALICIOUS_ATTACHMENT, f"VirusTotal flagged attachment as malicious: {attachment}")

    if ml_prediction == "PHISHING":
        assessment.add(round(ml_confidence), f"ML model predicted PHISHING ({ml_confidence:.1f}% confidence)")
    elif ml_unavailable_heuristics:
        if ml_unavailable_heuristics.get("suspicious_sender"):
            assessment.add(
                POINTS_HEURISTIC_SUSPICIOUS_SENDER,
                "ML model unavailable; sender address matches suspicious patterns",
            )
        if ml_unavailable_heuristics.get("urgent_subject"):
            assessment.add(
                POINTS_HEURISTIC_URGENT_SUBJECT,
                "ML model unavailable; subject uses urgency/pressure language",
            )

    if any_trusted_domain:
        assessment.add(POINTS_TRUSTED_DOMAIN, "Sender or link domain is on the trusted whitelist")

    if all_https:
        assessment.add(POINTS_ALL_HTTPS, "All links use HTTPS")

    if domain_age_days is not None and domain_age_days < 30:
        assessment.add(POINTS_DOMAIN_AGE_UNDER_30_DAYS, f"Domain registered {domain_age_days} day(s) ago (<30)")

    for reason in (homograph_findings or []):
        assessment.add(POINTS_HOMOGRAPH_DOMAIN, reason)

    for reason in (typosquat_findings or []):
        assessment.add(POINTS_TYPOSQUAT_DOMAIN, reason)

    for reason in (header_findings or []):
        assessment.add(POINTS_HEADER_FINDING, reason)

    return assessment
