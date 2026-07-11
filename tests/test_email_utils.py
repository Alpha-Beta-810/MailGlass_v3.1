"""Tests for email_utils.py's header-based signal extraction.

Covers the Reply-To / Return-Path / SPF / DKIM / DMARC / Received-chain
analysis, which is a second, independent line of evidence from the
URL/body/ML checks: forging a display name is trivial, but forging every
header along the delivery path is not.
"""

import os

import pytest

from email_utils import parse_eml_file

EML_DIR = os.path.join(os.path.dirname(__file__), "_tmp_eml")


@pytest.fixture(autouse=True)
def _tmp_eml_dir():
    os.makedirs(EML_DIR, exist_ok=True)
    yield
    for name in os.listdir(EML_DIR):
        os.remove(os.path.join(EML_DIR, name))
    os.rmdir(EML_DIR)


def _write_eml(name: str, content: str) -> str:
    path = os.path.join(EML_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class TestHeaderSignals:
    def test_matching_headers_produce_no_findings(self):
        path = _write_eml(
            "clean.eml",
            "From: alerts@bank.com\n"
            "Reply-To: alerts@bank.com\n"
            "Return-Path: <bounce@bank.com>\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            "Subject: Statement ready\n"
            "Content-Type: text/plain\n\n"
            "Your statement is ready.\n",
        )
        parsed = parse_eml_file(path)
        assert parsed.spf_result == "pass"
        assert parsed.dkim_result == "pass"
        assert parsed.dmarc_result == "pass"
        assert parsed.header_findings == []

    def test_mismatched_reply_to_and_return_path_are_flagged(self):
        path = _write_eml(
            "mismatch.eml",
            "From: alerts@bank.com\n"
            "Reply-To: attacker@evil-domain.com\n"
            "Return-Path: <bounce@another-evil.com>\n"
            "Subject: Verify your account\n"
            "Content-Type: text/plain\n\n"
            "Please verify.\n",
        )
        parsed = parse_eml_file(path)
        assert parsed.reply_to_domain == "evil-domain.com"
        assert parsed.return_path_domain == "another-evil.com"
        assert any("Reply-To domain" in f for f in parsed.header_findings)
        assert any("Return-Path domain" in f for f in parsed.header_findings)

    def test_failed_auth_results_are_flagged(self):
        path = _write_eml(
            "authfail.eml",
            "From: alerts@bank.com\n"
            "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bank.com; "
            "dkim=fail header.d=bank.com; dmarc=fail header.from=bank.com\n"
            "Subject: Verify your account\n"
            "Content-Type: text/plain\n\n"
            "Please verify.\n",
        )
        parsed = parse_eml_file(path)
        assert parsed.spf_result == "fail"
        assert parsed.dkim_result == "fail"
        assert parsed.dmarc_result == "fail"
        assert len(parsed.header_findings) == 3

    def test_received_hop_count(self):
        path = _write_eml(
            "hops.eml",
            "From: alerts@bank.com\n"
            "Received: from a by b\n"
            "Received: from b by c\n"
            "Received: from c by d\n"
            "Subject: Hi\n"
            "Content-Type: text/plain\n\n"
            "Hi.\n",
        )
        parsed = parse_eml_file(path)
        assert parsed.received_hop_count == 3

    def test_missing_headers_default_to_empty_without_errors(self):
        path = _write_eml(
            "bare.eml",
            "From: alerts@bank.com\n"
            "Subject: Hi\n"
            "Content-Type: text/plain\n\n"
            "Hi.\n",
        )
        parsed = parse_eml_file(path)
        assert parsed.reply_to == ""
        assert parsed.return_path == ""
        assert parsed.spf_result == ""
        assert parsed.dkim_result == ""
        assert parsed.dmarc_result == ""
        assert parsed.header_findings == []
