# Architecture Overview

This tool is designed as a small, composable CLI that can also be embedded as a library. Each component has a single responsibility and communicates through typed data classes.

## Components

- **DNS Resolver (`dns_resolver.py`)**: Wraps `dnspython` to issue TXT queries with predictable exceptions. Returns lightweight `TXTLookupResult` instances used by analyzers.
- **Analyzer Engine (`analyzer.py`)**: Parses the content of SPF, DMARC, and DKIM TXT records into structured analyses. The SPF parser tracks lookup-heavy mechanisms and fail modes; the DMARC parser extracts policy, reporting URIs, and sampling percentage.
- **Risk Calculator (`risk.py`)**: Applies opinionated rules from phishing defense operations to calculate the spoofability risk and summarize findings. The highest-severity issue sets the overall risk level.
- **Reporters (`report.py`)**: Convert risk reports into rich terminal tables or JSON payloads for automation.
- **Header Analyzer (`header_analysis.py`)**: Parses raw email headers to surface observed Authentication-Results outcomes.
- **CLI (`main.py`)**: Orchestrates resolution, analysis, scoring, and presentation. Supports both domain-based audits and raw header inspection.

## Data flow

1. `main.py` accepts CLI arguments and triggers either domain analysis or header parsing.
2. For domains, `DNSResolver` fetches TXT records for SPF, DMARC, and DKIM selectors.
3. `analyzer.parse_spf` and `analyzer.parse_dmarc` convert TXT content into structured analysis objects.
4. `risk.calculate_risk` consumes analyses to emit a `RiskReport` with a consolidated risk level and findings.
5. `report.render_terminal` or `report.to_json` formats the output for humans or systems.

## Error handling & logging

- DNS errors are surfaced as `DNSLookupError` or `TXTRecordNotFoundError`, enabling clean CLI messaging.
- Logging is centralized through the standard library and can be elevated with `--verbose`.

## Extensibility

- Add new checks (e.g., BIMI, MTA-STS) by extending analyzer functions and updating `RiskReport` aggregation rules.
- Implement additional output formats (HTML, CSV) by adding functions to `report.py` without changing core analysis logic.
