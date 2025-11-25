"""Command-line entrypoint for the Email Security Audit tool."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from analyzer import (
    DKIMAnalysis,
    DMARCAnalysis,
    SPFAnalysis,
    parse_dkim,
    parse_dmarc,
    parse_spf,
)
from dns_resolver import DNSLookupError, DNSResolver, TXTRecordNotFoundError
from header_analysis import parse_authentication_results
from report import render_terminal, to_json
from risk import RiskFinding, RiskReport, calculate_risk

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Email authentication audit tool")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--domain", help="Target domain to inspect")
    target.add_argument("--headers", type=Path, help="Path to raw email headers file")

    parser.add_argument(
        "--selector",
        default="default",
        help="DKIM selector to query when --domain is used (default: default)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of rich text")
    parser.add_argument("--output", type=Path, help="Write JSON output to file")
    parser.add_argument(
        "--verbose", action="store_true", help="Enable debug logging for troubleshooting"
    )
    return parser


def analyze_domain(domain: str, selector: str) -> str:
    """Analyze SPF, DMARC, and DKIM posture for a given domain and return JSON."""

    resolver = DNSResolver()

    try:
        spf_records = resolver.get_txt_records(domain).records
    except TXTRecordNotFoundError:
        spf_records = []
    except DNSLookupError as exc:
        logger.error("Unable to fetch SPF: %s", exc)
        spf_records = []

    spf_analysis = parse_spf(spf_records)

    try:
        dmarc_records = resolver.get_txt_records(f"_dmarc.{domain}").records
    except TXTRecordNotFoundError:
        dmarc_records = []
    except DNSLookupError as exc:
        logger.error("Unable to fetch DMARC: %s", exc)
        dmarc_records = []

    dmarc_analysis = parse_dmarc(dmarc_records)

    try:
        dkim_records = resolver.get_txt_records(f"{selector}._domainkey.{domain}").records
    except TXTRecordNotFoundError:
        dkim_records = []
    except DNSLookupError as exc:
        logger.error("Unable to fetch DKIM: %s", exc)
        dkim_records = []

    dkim_analysis = parse_dkim(selector, dkim_records)

    risk_report = calculate_risk(spf_analysis, dmarc_analysis, dkim_analysis)
    return to_json(risk_report)


def analyze_headers(path: Path) -> str:
    """Analyze raw email headers for Authentication-Results content."""

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Header file does not exist: {path}")

    header_text = path.read_text(encoding="utf-8")
    auth_result = parse_authentication_results(header_text)
    return json.dumps(auth_result.__dict__, indent=2)


def main() -> None:
    """CLI entrypoint for the email security audit tool."""

    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.domain:
        if not args.domain.strip():
            logger.error("--domain must not be empty")
            return
        result_json = analyze_domain(args.domain, args.selector)
    else:
        try:
            result_json = analyze_headers(args.headers)
        except FileNotFoundError as exc:
            logger.error(str(exc))
            return

    if args.json:
        print(result_json)
    else:
        try:
            payload = json.loads(result_json)
        except json.JSONDecodeError:
            logger.error("Unable to parse analysis result")
            return

        if "risk_level" in payload:
            # Domain path
            spf = SPFAnalysis(**payload["spf"])
            dmarc = DMARCAnalysis(**payload["dmarc"])
            dkim = DKIMAnalysis(**payload["dkim"])
            findings = [RiskFinding(**finding) for finding in payload["findings"]]
            report = RiskReport(spf=spf, dmarc=dmarc, dkim=dkim, findings=findings)
            render_terminal(report)
        else:
            print(result_json)

    if args.output:
        args.output.write_text(result_json, encoding="utf-8")


if __name__ == "__main__":
    main()
