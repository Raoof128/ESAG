"""DNS resolution utilities for email authentication records.

This module wraps dnspython to provide predictable error handling and response parsing
for SPF, DMARC, and DKIM TXT lookups.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)


class DNSLookupError(RuntimeError):
    """Raised when TXT lookup fails for reasons other than record absence."""


class TXTRecordNotFoundError(ValueError):
    """Raised when no TXT records are found for the requested name."""


@dataclass
class TXTLookupResult:
    """Container for TXT lookup data."""

    name: str
    records: list[str]


class DNSResolver:
    """Resolver for DNS TXT records with error handling suitable for CLI output."""

    def __init__(self, timeout: float = 3.0) -> None:
        """Create a resolver with a configured timeout in seconds."""

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def get_txt_records(self, name: str) -> TXTLookupResult:
        """Return TXT records for a name.

        Args:
            name: Domain or hostname to query.

        Raises:
            TXTRecordNotFoundError: No TXT records exist for the name.
            DNSLookupError: A non-recoverable DNS error occurred.
        """

        logger.debug("Looking up TXT records for %s", name)
        try:
            answers = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            raise TXTRecordNotFoundError(f"No TXT records found for {name}") from exc
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DNSLookupError(f"DNS query for {name} timed out or nameservers failed") from exc
        except dns.exception.DNSException as exc:  # pragma: no cover - defensive catch
            raise DNSLookupError(f"Unhandled DNS error for {name}: {exc}") from exc

        txt_values = [b"".join(rdata.strings).decode("utf-8") for rdata in answers]
        logger.debug("Found TXT records for %s: %s", name, txt_values)
        return TXTLookupResult(name=name, records=txt_values)
