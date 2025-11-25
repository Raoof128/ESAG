from header_analysis import AuthenticationResult, parse_authentication_results


def test_parse_authentication_results_extracts_outcomes():
    raw_headers = (
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=example.com; "
        "dkim=fail header.d=bad.example; dmarc=pass action=none"
    )
    result = parse_authentication_results(raw_headers)
    assert result == AuthenticationResult(spf="pass", dkim="fail", dmarc="pass", raw_header=result.raw_header)
    assert "mx.example.org" in result.raw_header


def test_parse_authentication_results_missing_header():
    result = parse_authentication_results("From: user@example.com\nSubject: hi")
    assert result == AuthenticationResult(spf=None, dkim=None, dmarc=None, raw_header=None)
