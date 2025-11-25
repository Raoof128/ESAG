# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability, email security-audit@example.com with details and reproduction steps. Please include any affected domains, headers, or redacted DNS output relevant to the finding.

We will acknowledge receipt within 72 hours and provide a timeline for remediation where possible. Please do not publicly disclose vulnerabilities until we have confirmed and addressed them.

## Supported Versions

Security fixes are applied to the latest `main` branch. Pin a specific release tag in production environments.

## Safe handling of data

- Do not submit real customer identifiers or unredacted email headers in issues.
- Use the `--json` flag when scripting to avoid parsing human-readable output.
- Validate DNS results before acting on them, especially in automation pipelines.
