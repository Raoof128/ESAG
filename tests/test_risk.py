from analyzer import DKIMAnalysis, DMARCAnalysis, SPFAnalysis
from risk import RiskLevel, calculate_risk


def test_risk_high_when_spf_missing():
    spf = SPFAnalysis(record=None)
    dmarc = DMARCAnalysis(record="v=DMARC1; p=reject", policy="reject", rua=None, pct=100)
    dkim = DKIMAnalysis(selector="default", record=None)
    report = calculate_risk(spf, dmarc, dkim)
    assert report.risk_level == RiskLevel.HIGH


def test_risk_medium_for_soft_fail_and_quarantine():
    spf = SPFAnalysis(record="v=spf1 ~all", has_soft_fail=True)
    dmarc = DMARCAnalysis(
        record="v=DMARC1; p=quarantine",
        policy="quarantine",
        rua="mailto:reports@example.com",
        pct=100,
    )
    dkim = DKIMAnalysis(
        selector="default",
        record="v=DKIM1; k=rsa; p=abc",
        key_type="rsa",
        has_public_key=True,
    )
    report = calculate_risk(spf, dmarc, dkim)
    assert report.risk_level == RiskLevel.MEDIUM


def test_risk_low_for_strong_spf_and_reject():
    spf = SPFAnalysis(record="v=spf1 -all", has_hard_fail=True)
    dmarc = DMARCAnalysis(
        record="v=DMARC1; p=reject", policy="reject", rua="mailto:reports@example.com", pct=100
    )
    dkim = DKIMAnalysis(
        selector="default",
        record="v=DKIM1; k=rsa; p=abc",
        key_type="rsa",
        has_public_key=True,
    )
    report = calculate_risk(spf, dmarc, dkim)
    assert report.risk_level == RiskLevel.LOW


def test_risk_flags_missing_dkim_key():
    spf = SPFAnalysis(record="v=spf1 -all", has_hard_fail=True)
    dmarc = DMARCAnalysis(record="v=DMARC1; p=reject", policy="reject", rua=None, pct=100)
    dkim = DKIMAnalysis(selector="default", record="v=DKIM1; k=rsa", key_type="rsa")
    report = calculate_risk(spf, dmarc, dkim)
    assert any(
        finding.level == RiskLevel.HIGH and "lacks a public key" in finding.message
        for finding in report.findings
    )
