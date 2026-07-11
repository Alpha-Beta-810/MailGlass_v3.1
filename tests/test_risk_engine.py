"""Tests for risk_engine.py's weighted scoring and verdict classification."""

from risk_engine import RiskAssessment, score_email


class TestRiskAssessment:
    def test_score_accumulates_and_ignores_zero_point_factors(self):
        assessment = RiskAssessment()
        assessment.add(50, "test factor")
        assessment.add(0, "should be ignored")
        assessment.add(-10, "negative factor")
        assert assessment.score == 40
        assert len(assessment.factors) == 2

    def test_verdict_thresholds(self):
        assert RiskAssessment(score=0).verdict == "SAFE"
        assert RiskAssessment(score=30).verdict == "SAFE"
        assert RiskAssessment(score=31).verdict == "SUSPICIOUS"
        assert RiskAssessment(score=60).verdict == "SUSPICIOUS"
        assert RiskAssessment(score=61).verdict == "MALICIOUS"
        assert RiskAssessment(score=150).verdict == "MALICIOUS"

    def test_negative_score_clamped_to_safe(self):
        assert RiskAssessment(score=-50).verdict == "SAFE"


class TestScoreEmail:
    def test_known_phishing_url_scores_malicious(self):
        assessment = score_email(
            url_verdicts={"https://evil.com": "malicious"},
            attachment_verdicts={},
        )
        assert assessment.score >= 100
        assert assessment.verdict == "MALICIOUS"

    def test_malicious_attachment_scores_malicious(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={"invoice.exe": "malicious"},
        )
        assert assessment.score >= 100
        assert assessment.verdict == "MALICIOUS"

    def test_trusted_domain_and_https_reduce_score(self):
        assessment = score_email(
            url_verdicts={"https://mckinsey.com": "whitelisted"},
            attachment_verdicts={},
            any_trusted_domain=True,
            all_https=True,
        )
        assert assessment.score < 0
        assert assessment.verdict == "SAFE"

    def test_ml_phishing_prediction_contributes_confidence_as_points(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            ml_prediction="PHISHING",
            ml_confidence=81.3,
        )
        assert assessment.score == 81
        assert assessment.verdict == "MALICIOUS"

    def test_ml_legitimate_prediction_contributes_nothing(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            ml_prediction="LEGITIMATE",
            ml_confidence=95.0,
        )
        assert assessment.score == 0
        assert assessment.verdict == "SAFE"

    def test_ml_unavailable_heuristics_fallback(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            ml_unavailable_heuristics={"suspicious_sender": True, "urgent_subject": True},
        )
        assert assessment.score == 30
        assert assessment.verdict == "SAFE"  # right at the boundary

    def test_homograph_finding_adds_points(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            homograph_findings=["xn--pple-43d.com: Punycode-encoded domain"],
        )
        assert assessment.score == 50
        assert assessment.verdict == "SUSPICIOUS"

    def test_young_domain_adds_points(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            domain_age_days=5,
        )
        assert assessment.score == 20

    def test_old_domain_adds_nothing(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            domain_age_days=3650,
        )
        assert assessment.score == 0

    def test_header_findings_add_points(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            header_findings=["Reply-To domain (evil.com) differs from sender domain (bank.com)"],
        )
        assert assessment.score == 20
        assert assessment.verdict == "SAFE"  # single finding stays under the SUSPICIOUS threshold

    def test_multiple_header_findings_stack(self):
        assessment = score_email(
            url_verdicts={},
            attachment_verdicts={},
            header_findings=["SPF check failed on this message", "DKIM check failed on this message"],
        )
        assert assessment.score == 40


class TestRiskLabel:
    def test_zero_score_is_very_low(self):
        assert RiskAssessment(score=0).risk_label == "Very Low"

    def test_high_score_is_critical(self):
        assert RiskAssessment(score=90).risk_label == "Critical"


class TestConfidence:
    def test_clean_signals_give_high_confidence(self):
        assessment = score_email(
            url_verdicts={"https://mckinsey.com": "whitelisted"},
            attachment_verdicts={},
            any_trusted_domain=True,
        )
        assert assessment.confidence == "High"

    def test_unknown_url_lowers_confidence(self):
        assessment = score_email(
            url_verdicts={"https://example.com": "unknown"},
            attachment_verdicts={},
        )
        assert assessment.confidence == "Medium"

    def test_unresolved_ml_and_unknown_url_gives_low_confidence(self):
        assessment = score_email(
            url_verdicts={"https://example.com": "unknown"},
            attachment_verdicts={},
            ml_unavailable_heuristics={"suspicious_sender": False, "urgent_subject": False},
        )
        assert assessment.confidence == "Low"
