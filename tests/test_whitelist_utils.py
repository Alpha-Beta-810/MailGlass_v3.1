"""Tests for whitelist_utils.py, especially subdomain vs. lookalike domain handling."""

from whitelist_utils import (
    get_domain_from_url,
    get_root_domain,
    is_sender_whitelisted,
    is_subdomain_of_trusted,
    is_whitelisted,
    normalize_domain,
)


class TestNormalizeDomain:
    def test_lowercases_and_strips_www(self):
        assert normalize_domain("WWW.McKinsey.com") == "mckinsey.com"
        assert normalize_domain("mckinsey.com") == "mckinsey.com"

    def test_strips_port_and_userinfo(self):
        assert normalize_domain("user@host.com:8080") == "host.com"


class TestGetRootDomain:
    def test_simple_domain(self):
        assert get_root_domain("links.mckinsey.com") == "mckinsey.com"
        assert get_root_domain("pages.careers.mckinsey.com") == "mckinsey.com"

    def test_multi_label_suffix(self):
        assert get_root_domain("mckinsey.co.uk") == "mckinsey.co.uk"
        assert get_root_domain("sub.mckinsey.co.uk") == "mckinsey.co.uk"

    def test_lookalike_domain_is_its_own_root(self):
        assert get_root_domain("mckinsey-login.com") == "mckinsey-login.com"


class TestIsSubdomainOfTrusted:
    def test_trusted_subdomains_match(self):
        assert is_subdomain_of_trusted("links.mckinsey.com", "mckinsey.com") is True
        assert is_subdomain_of_trusted("pages.mckinsey.com", "mckinsey.com") is True
        assert is_subdomain_of_trusted("careers.mckinsey.com", "mckinsey.com") is True
        assert is_subdomain_of_trusted("mckinsey.com", "mckinsey.com") is True

    def test_lookalike_domain_does_not_match(self):
        """The exact case the original substring-matching whitelist got wrong."""
        assert is_subdomain_of_trusted("mckinsey-login.com", "mckinsey.com") is False
        assert is_subdomain_of_trusted("notmckinsey.com", "mckinsey.com") is False
        assert is_subdomain_of_trusted("mckinsey.com.evil.tld", "mckinsey.com") is False


class TestIsWhitelisted:
    def setup_method(self):
        self.whitelist = {
            "exactMatching": {"url": ["https://exact.example.com/page"], "domain": []},
            "domainsInSubdomains": ["mckinsey.com"],
            "domainsInURLs": [],
            "domainsInEmails": [],
        }

    def test_exact_url_match(self):
        assert is_whitelisted("https://exact.example.com/page", self.whitelist) is True

    def test_subdomain_of_trusted_domain(self):
        assert is_whitelisted("https://links.mckinsey.com/abc123", self.whitelist) is True
        assert is_whitelisted("https://www.mckinsey.com/careers", self.whitelist) is True

    def test_lookalike_not_whitelisted(self):
        assert is_whitelisted("https://mckinsey-login.com/verify", self.whitelist) is False

    def test_unrelated_domain_not_whitelisted(self):
        assert is_whitelisted("https://totally-unrelated.com", self.whitelist) is False


class TestIsSenderWhitelisted:
    def test_trusted_sender_domain(self):
        whitelist = {"domainsInSubdomains": ["mckinsey.com"], "exactMatching": {"domain": []},
                     "domainsInURLs": [], "domainsInEmails": []}
        assert is_sender_whitelisted("insights@links.mckinsey.com", whitelist) is True
        assert is_sender_whitelisted("phisher@mckinsey-login.com", whitelist) is False
