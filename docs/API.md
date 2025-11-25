# API and Module Reference

This document summarizes the primary modules and callable interfaces provided by the Email Security Audit tool.

## `dns_resolver`
- **`DNSResolver.get_txt_records(name: str) -> TXTLookupResult`**: Perform TXT lookups with hardened error handling.
- **Exceptions**: `TXTRecordNotFoundError` when no TXT records are present, `DNSLookupError` for timeouts or other resolver errors.

## `analyzer`
- **`parse_spf(records: list[str]) -> SPFAnalysis`**: Extract SPF mechanisms, fail modes, and DNS lookup counts.
- **`parse_dmarc(records: list[str]) -> DMARCAnalysis`**: Parse DMARC tags (`p`, `rua`, `pct`) into a structured analysis.
- **`parse_dkim(selector: str, records: list[str]) -> DKIMAnalysis`**: Parse DKIM selector records, noting key type, service flags, and whether a public key is present.

## `risk`
- **`calculate_risk(spf: SPFAnalysis, dmarc: DMARCAnalysis, dkim: DKIMAnalysis) -> RiskReport`**: Aggregate findings and derive the composite `risk_level` (`LOW`, `MEDIUM`, `HIGH`).
- **`RiskReport` fields**: `spf`, `dmarc`, `dkim`, `findings`, plus the computed `risk_level` property.

## `report`
- **`render_terminal(report: RiskReport) -> None`**: Display a rich table summarizing SPF/DMARC/DKIM state and risk findings.
- **`to_json(report: RiskReport) -> str`**: Serialize the report for pipelines.

## `header_analysis`
- **`parse_authentication_results(header_blob: str) -> AuthenticationResult`**: Parse Authentication-Results headers to observe receiver-side SPF/DKIM/DMARC outcomes.

## CLI (`main.py`)
- Entry point invoked via `python main.py`. Key functions:
  - **`build_parser()`**: Defines CLI arguments.
  - **`analyze_domain(domain: str, selector: str)`**: Orchestrates DNS resolution, analysis, and risk scoring.
  - **`analyze_headers(path: Path)`**: Parse a header file for Authentication-Results.

All public functions include type hints and docstrings; see in-file documentation for full parameter semantics and error cases.
