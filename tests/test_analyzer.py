from analyzer import DKIMAnalysis, DMARCAnalysis, parse_dkim, parse_dmarc, parse_spf


def test_parse_spf_flags_allows_and_fail_modes():
    record = ["v=spf1 ip4:203.0.113.0/24 include:example.com ~all"]
    result = parse_spf(record)
    assert result.record == record[0]
    assert result.has_soft_fail is True
    assert result.has_hard_fail is False
    assert result.has_allow_all is False
    assert result.lookup_count == 1
    assert result.too_many_lookups is False


def test_parse_spf_detects_allow_all_and_lookup_limit():
    record = [
        "v=spf1 include:example.com include:example.net include:example.org include:a.example.com "
        "include:b.example.com include:c.example.com include:d.example.com include:e.example.com "
        "include:f.example.com include:g.example.com include:h.example.com +all"
    ]
    result = parse_spf(record)
    assert result.has_allow_all is True
    assert result.too_many_lookups is True


def test_parse_spf_missing_returns_empty_analysis():
    result = parse_spf([])
    assert result.record is None
    assert result.mechanisms == []


def test_parse_spf_handles_mixed_case_tokens_and_lookups():
    record = ["v=SPF1 INCLUDE:Example.com MX -ALL"]
    result = parse_spf(record)
    assert result.mechanisms == ["include:example.com", "mx", "-all"]
    assert result.lookup_count == 2  # include + mx
    assert result.has_hard_fail is True


def test_parse_dmarc_parses_tags():
    records = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"]
    result = parse_dmarc(records)
    assert result.policy == "reject"
    assert result.rua == "mailto:dmarc@example.com"
    assert result.pct == 100


def test_parse_dmarc_missing_returns_empty_analysis():
    result = parse_dmarc([])
    assert result == DMARCAnalysis(record=None, policy=None, rua=None, pct=None)


def test_parse_dkim_parses_tags():
    records = ["v=DKIM1; k=rsa; t=s; p=abc123"]
    result = parse_dkim("default", records)
    assert result == DKIMAnalysis(
        selector="default",
        record=records[0],
        key_type="rsa",
        service_type="s",
        has_public_key=True,
    )
