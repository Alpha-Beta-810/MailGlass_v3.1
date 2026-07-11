"""Tests for url_utils.py, including the original href-extraction bug fix."""

from url_utils import (
    extract_urls_from_html,
    extract_urls_from_text,
    extract_visible_text,
    is_valid_url,
    merge_urls,
)


class TestIsValidUrl:
    def test_rejects_bare_domains(self):
        assert is_valid_url("McKinsey.org") is False
        assert is_valid_url("paypal.com") is False
        assert is_valid_url("google.com") is False
        assert is_valid_url("example.net") is False

    def test_accepts_http_https_urls(self):
        assert is_valid_url("https://mckinsey.org") is True
        assert is_valid_url("https://paypal.com/login") is True
        assert is_valid_url("http://example.net") is True

    def test_rejects_non_web_schemes(self):
        assert is_valid_url("javascript:void(0)") is False
        assert is_valid_url("mailto:someone@example.com") is False
        assert is_valid_url("tel:+15551234567") is False
        assert is_valid_url("data:text/plain;base64,aGVsbG8=") is False

    def test_rejects_empty_or_malformed(self):
        assert is_valid_url("") is False
        assert is_valid_url(None) is False
        assert is_valid_url("https://") is False


class TestExtractUrlsFromHtml:
    def test_extracts_href_not_anchor_text(self):
        """The core bug: destination must come from href, not visible text."""
        html = '<a href="https://links.mckinsey.com/abc123">McKinsey.org</a>'
        urls, anchors = extract_urls_from_html(html)
        assert urls == ["https://links.mckinsey.com/abc123"]
        assert anchors["https://links.mckinsey.com/abc123"] == "McKinsey.org"

    def test_ignores_non_web_schemes(self):
        html = (
            '<a href="mailto:a@b.com">Email</a>'
            '<a href="javascript:alert(1)">Click</a>'
            '<a href="https://example.com">Real link</a>'
        )
        urls, _ = extract_urls_from_html(html)
        assert urls == ["https://example.com"]

    def test_deduplicates_within_html(self):
        html = (
            '<a href="https://example.com/a">One</a>'
            '<a href="https://example.com/a">Duplicate</a>'
        )
        urls, _ = extract_urls_from_html(html)
        assert urls.count("https://example.com/a") == 1

    def test_handles_malformed_html_without_raising(self):
        urls, anchors = extract_urls_from_html("<a href='https://example.com'>unclosed")
        assert "https://example.com" in urls

    def test_empty_html_returns_empty(self):
        assert extract_urls_from_html("") == ([], {})
        assert extract_urls_from_html(None) == ([], {})


class TestExtractVisibleText:
    def test_strips_markup(self):
        html = "<html><body><p>Hello <b>world</b></p></body></html>"
        text = extract_visible_text(html)
        assert "Hello" in text and "world" in text
        assert "<" not in text

    def test_anchor_text_extraction_matches_original_bug_report(self):
        """Confirms get_text() collapses the anchor as the original code
        found - which is exactly why href-based extraction is required."""
        html = '<a href="https://links.mckinsey.com/abc123">McKinsey.org</a>'
        assert extract_visible_text(html) == "McKinsey.org"


class TestExtractUrlsFromText:
    def test_finds_http_https_urls(self):
        text = "Visit https://example.com/path or http://other.com."
        urls = extract_urls_from_text(text)
        assert "https://example.com/path" in urls
        assert "http://other.com" in urls

    def test_ignores_bare_domains_in_text(self):
        text = "Contact us at paypal.com for details."
        assert extract_urls_from_text(text) == []

    def test_strips_trailing_punctuation(self):
        text = "See (https://example.com/page)."
        urls = extract_urls_from_text(text)
        assert urls == ["https://example.com/page"]


class TestMergeUrls:
    def test_merges_and_dedupes_preserving_order(self):
        merged = merge_urls(["a", "b"], ["b", "c"], ["a", "d"])
        assert merged == ["a", "b", "c", "d"]
