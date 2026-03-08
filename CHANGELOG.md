# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-07

### Added

- Initial release of the SOC triage agent.
- LLM-powered alert severity and category classification.
- IOC extraction engine with regex-based detection for IPs, domains, hashes, URLs, CVEs.
- Threat intelligence integration with VirusTotal, AbuseIPDB, and AlienVault OTX.
- Event correlation engine with temporal and IOC-based grouping.
- SIEM connectors for Splunk, Microsoft Sentinel, and Elastic Security.
- Generic webhook receiver with HMAC signature verification.
- YAML-based response playbook engine with conditional step execution.
- Ticket creation for Jira and ServiceNow.
- Notifications via Slack, Microsoft Teams, PagerDuty, and email.
- Full triage pipeline with batch processing support.
- Example scripts for single alert and batch triage workflows.
