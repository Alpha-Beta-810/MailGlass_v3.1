"""Tests for typosquat_detection.py."""

from typosquat_detection import detect_typosquat, scan_domains_for_typosquats


class TestDetectTyposquat:
    def test_trusted_root_domain_not_flagged(self):
        is_typosquat, _ = detect_typosquat("mckinsey.com")
        assert is_typosquat is False

    def test_legitimate_subdomain_not_flagged(self):
        is_typosquat, _ = detect_typosquat("links.mckinsey.com")
        assert is_typosquat is False

    def test_unrelated_domain_not_flagged(self):
        is_typosquat, _ = detect_typosquat("some-unrelated-blog.com")
        assert is_typosquat is False

    def test_combosquat_hyphen_suffix_is_flagged(self):
        is_typosquat, reason = detect_typosquat("mckinsey-login.com")
        assert is_typosquat is True
        assert "mckinsey" in reason

    def test_combosquat_paypal_is_flagged(self):
        is_typosquat, reason = detect_typosquat("paypal-secure-verify.com")
        assert is_typosquat is True

    def test_character_substitution_paypal_is_flagged(self):
        is_typosquat, reason = detect_typosquat("paypa1.com")
        assert is_typosquat is True
        assert "edit distance" in reason

    def test_character_substitution_google_is_flagged(self):
        is_typosquat, _ = detect_typosquat("g00gle.com")
        assert is_typosquat is True

    def test_character_substitution_microsoft_is_flagged(self):
        is_typosquat, _ = detect_typosquat("micr0soft.com")
        assert is_typosquat is True

    def test_suffix_swap_is_flagged(self):
        is_typosquat, reason = detect_typosquat("mckinsey.net")
        assert is_typosquat is True
        assert "suffix" in reason

    def test_empty_domain_not_flagged(self):
        is_typosquat, reason = detect_typosquat("")
        assert is_typosquat is False
        assert reason == ""

    def test_bare_label_without_dot_not_flagged(self):
        is_typosquat, _ = detect_typosquat("localhost")
        assert is_typosquat is False

    def test_whitelisted_extra_brand_domain_not_flagged(self):
        whitelist = {"typosquatBrands": ["examplecorp.com"]}
        is_typosquat, _ = detect_typosquat("examplecorp.com", whitelist)
        assert is_typosquat is False

    def test_extra_brand_typosquat_is_flagged(self):
        whitelist = {"typosquatBrands": ["examplecorp.com"]}
        is_typosquat, _ = detect_typosquat("examplecorp-login.com", whitelist)
        assert is_typosquat is True

    def test_domain_already_trusted_via_subdomains_list_not_flagged(self):
        # A brand-lookalike label that IS explicitly trusted elsewhere in
        # the whitelist must never be flagged, even if it also happens to
        # be close to a curated brand.
        whitelist = {"domainsInSubdomains": ["mckinsey-login.com"]}
        is_typosquat, _ = detect_typosquat("mckinsey-login.com", whitelist)
        assert is_typosquat is False


class TestScanDomainsForTyposquats:
    def test_returns_only_flagged_domains(self):
        findings = scan_domains_for_typosquats(["mckinsey.com", "mckinsey-login.com", "google.com"])
        assert len(findings) == 1
        assert "mckinsey-login.com" in findings[0]

    def test_dedupes_repeated_domains(self):
        findings = scan_domains_for_typosquats(["paypa1.com", "paypa1.com", "PAYPA1.COM"])
        assert len(findings) == 1

    def test_no_findings_returns_empty_list(self):
        findings = scan_domains_for_typosquats(["mckinsey.com", "google.com"])
        assert findings == []
