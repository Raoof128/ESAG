"""Parsers and analysis helpers for SPF, DMARC, and DKIM records."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


@dataclass
class SPFAnalysis:
    """Represents the analyzed state of an SPF record."""

    record: str | None
    mechanisms: list[str] = field(default_factory=list)
    has_soft_fail: bool = False
    has_hard_fail: bool = False
    has_allow_all: bool = False
    lookup_count: int = 0
    too_many_lookups: bool = False


@dataclass
class DMARCAnalysis:
    """Represents the analyzed state of a DMARC policy record."""

    record: str | None
    policy: str | None
    rua: str | None
    pct: int | None


@dataclass
class DKIMAnalysis:
    """Represents the analyzed state of a DKIM key record."""

    selector: str
    record: str | None
    key_type: str | None = None
    service_type: str | None = None
    has_public_key: bool = False


def parse_spf(records: list[str]) -> SPFAnalysis:
    """Parse SPF records and return an analysis object.

    The function extracts mechanisms, fail modes, and lookup-heavy directives such as
    ``include``. SPF lookups are limited to 10 per RFC 7208; exceeding this number is
    risky because receivers may stop evaluating the policy.
    """

    spf_record = next((rec for rec in records if rec.lower().startswith("v=spf1")), None)
    if spf_record is None:
        logger.debug("No SPF record detected in %s", records)
        return SPFAnalysis(record=None)

    tokens = [token.lower() for token in spf_record.split()]
    mechanisms = [token for token in tokens[1:] if not token.startswith("exp=")]

    lookup_count = sum(1 for token in mechanisms if _is_lookup_mechanism(token))
    has_allow_all = any(token.endswith("+all") or token == "+all" for token in mechanisms)
    has_soft_fail = any(token.endswith("~all") or token == "~all" for token in mechanisms)
    has_hard_fail = any(token.endswith("-all") or token == "-all" for token in mechanisms)

    too_many_lookups = lookup_count > 10

    analysis = SPFAnalysis(
        record=spf_record,
        mechanisms=mechanisms,
        has_soft_fail=has_soft_fail,
        has_hard_fail=has_hard_fail,
        has_allow_all=has_allow_all,
        lookup_count=lookup_count,
        too_many_lookups=too_many_lookups,
    )
    logger.debug("SPF analysis result: %s", analysis)
    return analysis


def _is_lookup_mechanism(token: str) -> bool:
    """Return True if SPF token triggers an additional DNS lookup."""

    mechanism = token.split(":", 1)[0].lstrip("+~-?").lower()
    return mechanism in SPF_LOOKUP_MECHANISMS


def parse_dmarc(records: list[str]) -> DMARCAnalysis:
    """Parse DMARC records and return an analysis object."""

    dmarc_record = next((rec for rec in records if rec.lower().startswith("v=dmarc1")), None)
    if dmarc_record is None:
        return DMARCAnalysis(record=None, policy=None, rua=None, pct=None)

    tag_pattern = re.compile(r"(?P<key>[a-zA-Z]+)=(?P<value>[^;\s]+)")
    tags: dict[str, str] = {
        match.group("key").lower(): match.group("value")
        for match in tag_pattern.finditer(dmarc_record)
    }

    pct_value = tags.get("pct")
    pct: int | None = int(pct_value) if pct_value and pct_value.isdigit() else None

    analysis = DMARCAnalysis(
        record=dmarc_record,
        policy=tags.get("p"),
        rua=tags.get("rua"),
        pct=pct,
    )
    logger.debug("DMARC analysis result: %s", analysis)
    return analysis


def parse_dkim(selector: str, records: list[str]) -> DKIMAnalysis:
    """Parse DKIM selector TXT records into structured data."""

    dkim_record = next((rec for rec in records if rec.lower().startswith("v=dkim1")), None)
    if dkim_record is None:
        return DKIMAnalysis(selector=selector, record=None)

    tag_pattern = re.compile(r"(?P<key>[a-zA-Z]+)=(?P<value>[^;\s]+)")
    tags: dict[str, str] = {
        match.group("key").lower(): match.group("value")
        for match in tag_pattern.finditer(dkim_record)
    }

    public_key = tags.get("p")
    has_public_key = bool(public_key and public_key != "\"\"")

    analysis = DKIMAnalysis(
        selector=selector,
        record=dkim_record,
        key_type=tags.get("k"),
        service_type=tags.get("t"),
        has_public_key=has_public_key,
    )
    logger.debug("DKIM analysis result: %s", analysis)
    return analysis
