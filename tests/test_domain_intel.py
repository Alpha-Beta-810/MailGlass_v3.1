"""Tests for domain_intel.py: homograph/punycode detection and WHOIS fallback safety."""

from domain_intel import decode_idn_domain, detect_homograph_risk, get_domain_age_days


class TestDetectHomographRisk:
    def test_plain_latin_domain_is_not_flagged(self):
        is_suspicious, reason = detect_homograph_risk("mckinsey.com")
        assert is_suspicious is False
        assert reason == ""

    def test_lookalike_ascii_domain_is_not_flagged_by_this_heuristic(self):
        """Pure-ASCII lookalikes (mckinsey-login.com) are a whitelist-matching
        concern, not a script-mixing one - this heuristic only catches
        Unicode-based visual spoofing."""
        is_suspicious, _ = detect_homograph_risk("mckinsey-login.com")
        assert is_suspicious is False

    def test_punycode_domain_is_flagged(self):
        is_suspicious, reason = detect_homograph_risk("xn--pple-43d.com")
        assert is_suspicious is True
        assert "punycode" in reason.lower()

    def test_mixed_script_domain_is_flagged(self):
        # "а" here is Cyrillic (U+0430), rest is Latin - classic homograph attack.
        mixed = "\u0430pple.com"
        is_suspicious, reason = detect_homograph_risk(mixed)
        assert is_suspicious is True
        assert "script" in reason.lower()

    def test_empty_domain_is_not_flagged(self):
        is_suspicious, reason = detect_homograph_risk("")
        assert is_suspicious is False
        assert reason == ""


class TestDecodeIdnDomain:
    def test_non_punycode_domain_unchanged(self):
        assert decode_idn_domain("mckinsey.com") == "mckinsey.com"

    def test_decodes_punycode_label(self):
        decoded = decode_idn_domain("xn--pple-43d.com")
        assert decoded != "xn--pple-43d.com"
        assert "pple" in decoded

    def test_empty_domain_unchanged(self):
        assert decode_idn_domain("") == ""


class TestGetDomainAgeDays:
    def test_never_raises_on_bad_input(self):
        # Whatever the environment's WHOIS/network situation, this must not raise.
        result = get_domain_age_days("this-domain-almost-certainly-does-not-exist-12345.test")
        assert result is None or isinstance(result, int)

    def test_empty_domain_returns_none(self):
        assert get_domain_age_days("") is None
