"""Risk calculation logic for spoofability scoring."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List

from analyzer import DKIMAnalysis, DMARCAnalysis, SPFAnalysis


class RiskLevel(str, Enum):
    """High-level spoofability risk ratings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class RiskFinding:
    """A single risk observation used in the final report."""

    message: str
    level: RiskLevel


@dataclass
class RiskReport:
    """Aggregated risk report."""

    spf: SPFAnalysis
    dmarc: DMARCAnalysis
    dkim: DKIMAnalysis
    findings: List[RiskFinding]

    @property
    def risk_level(self) -> RiskLevel:
        """Return the highest severity level represented in the findings."""

        if any(f.level == RiskLevel.HIGH for f in self.findings):
            return RiskLevel.HIGH
        if any(f.level == RiskLevel.MEDIUM for f in self.findings):
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


def calculate_risk(spf: SPFAnalysis, dmarc: DMARCAnalysis, dkim: DKIMAnalysis) -> RiskReport:
    """Generate a spoofability risk report from SPF, DMARC, and DKIM analyses."""

    findings: List[RiskFinding] = []

    # SPF evaluation
    if spf.record is None:
        findings.append(RiskFinding("SPF missing", RiskLevel.HIGH))
    else:
        if spf.has_allow_all:
            findings.append(RiskFinding("SPF contains +all allowing spoofing", RiskLevel.HIGH))
        if spf.has_soft_fail and not spf.has_hard_fail:
            findings.append(RiskFinding("SPF uses ~all (soft fail)", RiskLevel.MEDIUM))
        if spf.too_many_lookups:
            findings.append(RiskFinding("SPF exceeds 10 DNS lookup limit", RiskLevel.MEDIUM))
        if spf.has_hard_fail and not spf.has_allow_all and not spf.too_many_lookups:
            findings.append(RiskFinding("SPF enforces -all", RiskLevel.LOW))

    # DMARC evaluation
    if dmarc.record is None:
        findings.append(RiskFinding("DMARC missing", RiskLevel.HIGH))
    else:
        if dmarc.policy is None:
            findings.append(RiskFinding("DMARC policy undefined", RiskLevel.HIGH))
        elif dmarc.policy.lower() == "none":
            findings.append(RiskFinding("DMARC p=none (monitor only)", RiskLevel.HIGH))
        elif dmarc.policy.lower() == "quarantine":
            findings.append(RiskFinding("DMARC p=quarantine", RiskLevel.MEDIUM))
        elif dmarc.policy.lower() == "reject":
            findings.append(RiskFinding("DMARC p=reject", RiskLevel.LOW))

        if dmarc.rua is None:
            findings.append(
                RiskFinding("DMARC rua missing (no aggregate reports)", RiskLevel.MEDIUM)
            )

    # DKIM evaluation
    if dkim.record is None:
        findings.append(
            RiskFinding(
                f"DKIM selector '{dkim.selector}' missing (no signing key advertised)",
                RiskLevel.MEDIUM,
            )
        )
    else:
        if not dkim.has_public_key:
            findings.append(
                RiskFinding(
                    f"DKIM selector '{dkim.selector}' lacks a public key (p= missing)",
                    RiskLevel.HIGH,
                )
            )
        else:
            findings.append(
                RiskFinding(
                    f"DKIM selector '{dkim.selector}' publishes a signing key",
                    RiskLevel.LOW,
                )
            )
        if dkim.key_type and dkim.key_type.lower() not in {"rsa", "ed25519"}:
            findings.append(
                RiskFinding(
                    f"DKIM selector '{dkim.selector}' uses uncommon key type {dkim.key_type}",
                    RiskLevel.MEDIUM,
                )
            )

    return RiskReport(spf=spf, dmarc=dmarc, dkim=dkim, findings=findings)
