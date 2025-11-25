"""Helpers for parsing authentication results from raw email headers."""

from __future__ import annotations

import email
import re
from dataclasses import dataclass
from email.message import Message
from typing import Dict, Optional


@dataclass
class AuthenticationResult:
    """Represents a simplified Authentication-Results summary."""

    spf: Optional[str]
    dkim: Optional[str]
    dmarc: Optional[str]
    raw_header: Optional[str]


_AUTH_RESULTS_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=(?P<value>[a-zA-Z0-9_-]+)")


def parse_authentication_results(header_blob: str) -> AuthenticationResult:
    """Parse Authentication-Results from a raw header string.

    The parser intentionally extracts only the pass/fail result tokens for SPF, DKIM,
    and DMARC to provide a high-level view of receiver evaluation. Additional detail
    (e.g., IP addresses, reasons) is left untouched to avoid overfitting to provider-
    specific formats.
    """

    message: Message = email.message_from_string(header_blob)
    auth_header = message.get("Authentication-Results")
    if auth_header is None:
        return AuthenticationResult(spf=None, dkim=None, dmarc=None, raw_header=None)

    findings: Dict[str, str] = {}
    for match in _AUTH_RESULTS_PATTERN.finditer(auth_header):
        mechanism = match.group(1).lower()
        findings[mechanism] = match.group("value").lower()

    return AuthenticationResult(
        spf=findings.get("spf"),
        dkim=findings.get("dkim"),
        dmarc=findings.get("dmarc"),
        raw_header=auth_header,
    )
