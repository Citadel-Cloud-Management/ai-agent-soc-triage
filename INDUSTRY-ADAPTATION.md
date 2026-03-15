# Industry Adaptation Guide

## Overview
The `ai-agent-soc-triage` project is an AI-powered SOC (Security Operations Center) triage engine that classifies alerts, extracts IOCs, correlates events, enriches with threat intelligence (VirusTotal, AbuseIPDB, OTX), creates tickets (Jira, ServiceNow), sends notifications (Slack, Teams, PagerDuty, email), and executes response playbooks. It integrates with Splunk, Sentinel, and Elastic SIEMs. Its pluggable architecture makes it adaptable to any industry's security operations.

## Healthcare
### Compliance Requirements
- HIPAA, HITRUST, HL7 FHIR
### Configuration Changes
- Set `SIEMConfig.provider` to match the organization's SIEM (commonly `SIEMProvider.SENTINEL` for Azure-centric health IT or `SIEMProvider.SPLUNK` for on-premises deployments).
- Configure `ThreatIntelConfig` with healthcare-specific threat intelligence feeds focused on ransomware and PHI exfiltration IOCs.
- Set `TriageConfig.auto_respond_threshold = "critical"` and `enable_auto_response = False` initially, requiring human approval for actions affecting PHI systems.
- Create custom playbooks in `playbook_directory` for healthcare-specific scenarios: ransomware targeting EHR systems, unauthorized PHI access, medical device network anomalies.
- Configure `TicketConfig` with `project_key` mapped to a HIPAA incident tracking project.
- Set `NotificationConfig.channels` to include `NotificationChannel.PAGERDUTY` for critical PHI breach alerts.
- Set `LLMConfig` to use a HIPAA-eligible AI provider or self-hosted model.
- Set `max_correlation_window_minutes = 30` for rapid PHI breach detection.
### Example Use Case
A hospital SOC uses the triage agent to classify alerts from Sentinel, correlate unauthorized EHR access patterns within 30-minute windows, enrich suspicious IPs through threat intelligence, auto-create HIPAA incident tickets in ServiceNow, and page the security team via PagerDuty for confirmed PHI breaches.

## Finance
### Compliance Requirements
- SOX, PCI-DSS, SOC 2
### Configuration Changes
- Configure `SIEMConfig` with the financial institution's SIEM (commonly Splunk Enterprise Security).
- Create custom playbooks for financial scenarios: payment card skimming, wire fraud indicators, insider trading detection, account takeover.
- Set `TriageConfig.auto_respond_threshold = "high"` with `enable_auto_response = True` for automated containment of confirmed fraud indicators.
- Configure `ThreatIntelConfig` with financial sector-specific threat feeds.
- Set `TicketConfig.provider = TicketProvider.SERVICENOW` with project keys mapped to SOX-auditable incident workflows.
- Set `NotificationConfig.channels` to include `NotificationChannel.PAGERDUTY` and `NotificationChannel.SLACK` for tiered alerting.
- Set `max_correlation_window_minutes = 15` for rapid detection of coordinated attacks.
### Example Use Case
A bank deploys the triage agent to process Splunk alerts, auto-correlate brute force and account takeover attempts within 15-minute windows, run the fraud detection playbook to block compromised accounts, and create SOX-auditable ServiceNow tickets.

## Government
### Compliance Requirements
- FedRAMP, CMMC, NIST 800-53
### Configuration Changes
- Set `LLMConfig.provider` to a FedRAMP-authorized AI provider or self-hosted model in a GovCloud environment.
- Configure `SIEMConfig` for the agency's SIEM (commonly Splunk or Elastic in government environments).
- Create custom playbooks for government scenarios: APT detection, insider threat, unauthorized CUI access, supply chain compromise.
- Set `enable_auto_response = False` for all actions requiring human authorization per NIST IR-4 incident handling procedures.
- Configure `TicketConfig` to integrate with the agency's FISMA-compliant incident tracking system.
- Set `max_correlation_window_minutes = 60` for correlating low-and-slow APT activity.
- Set `NotificationConfig.channels` to include approved government notification channels.
- Set `SIEMConfig.verify_ssl = true` for all connections.
### Example Use Case
A federal agency deploys the triage agent in GovCloud to process Elastic SIEM alerts, correlate potential APT activity over 60-minute windows, enrich IOCs through government-approved threat feeds, and create FISMA incident tickets requiring analyst approval before any automated response.

## Retail / E-Commerce
### Compliance Requirements
- PCI-DSS, CCPA/GDPR
### Configuration Changes
- Configure `SIEMConfig` for the retailer's SIEM (commonly Splunk or Elastic).
- Create custom playbooks for retail scenarios: web scraping/bot detection, payment card fraud, customer account takeover, supply chain API compromise.
- Set `TriageConfig.auto_respond_threshold = "high"` with `enable_auto_response = True` for automated blocking of confirmed bot attacks and card fraud.
- Configure `ThreatIntelConfig` with e-commerce threat feeds.
- Set `TicketConfig` with project keys for PCI incident tracking.
- Set `max_correlation_window_minutes = 30` for correlating distributed attacks during peak shopping periods.
- Configure `NotificationConfig` with Slack for the security team and email for executive escalation.
### Example Use Case
A retailer deploys the triage agent to detect coordinated bot attacks during Black Friday, correlate payment fraud indicators within 30-minute windows, auto-block confirmed malicious IPs via the response playbook, and alert the PCI incident response team via Slack.

## Education
### Compliance Requirements
- FERPA, COPPA
### Configuration Changes
- Configure `SIEMConfig` for the institution's SIEM platform.
- Create custom playbooks for education scenarios: unauthorized student record access, phishing targeting faculty, ransomware, student data exfiltration.
- Set `enable_auto_response = False` requiring human approval for actions affecting student data systems.
- Configure `TicketConfig` with project keys mapped to FERPA incident reporting workflows.
- Set `NotificationConfig.channels` to include `NotificationChannel.EMAIL` for required FERPA breach notifications.
- Configure `ThreatIntelConfig` with education-sector threat feeds (REN-ISAC).
### Example Use Case
A university SOC uses the triage agent to classify phishing alerts targeting faculty credentials, correlate unauthorized student record access events, auto-create FERPA incident tickets, and notify the CISO and registrar via email for confirmed student data exposure.

## SaaS / Multi-Tenant
### Compliance Requirements
- SOC 2, ISO 27001
### Configuration Changes
- Configure `SIEMConfig` to connect to a centralized SIEM aggregating logs from all tenant environments.
- Create custom playbooks for SaaS scenarios: cross-tenant data access, API key compromise, tenant impersonation, DDoS targeting specific tenants.
- Set `TriageConfig.auto_respond_threshold = "critical"` with `enable_auto_response = True` for automated containment of confirmed cross-tenant breaches.
- Configure `TicketConfig` with tenant-aware project keys for SOC 2 incident tracking.
- Set `max_correlation_window_minutes = 45` for correlating multi-tenant attack patterns.
- Configure `NotificationConfig` with per-tenant Slack channels or webhook URLs via `NotificationChannel.SLACK`.
- Set `LLMConfig.temperature = 0.0` for deterministic triage results across tenants.
### Example Use Case
A SaaS provider deploys the triage agent to monitor its multi-tenant environment, detect cross-tenant data access anomalies, correlate API key abuse patterns across tenants, auto-create SOC 2 incident tickets per affected tenant, and notify tenant security contacts.

## Cross-Industry Best Practices
- Use environment-based configuration via `TriageConfig.from_env()` to load settings from environment variables per deployment environment.
- Always enable encryption in transit by setting `SIEMConfig.verify_ssl = true` for all SIEM connections.
- Enable audit logging and monitoring by forwarding triage decisions and playbook executions to the SIEM for a complete audit trail.
- Enforce least-privilege access controls by restricting `LLMConfig.api_key`, `SIEMConfig.api_key`, and `TicketConfig.api_key` to minimum required permissions.
- Implement network segmentation by deploying the triage agent in a dedicated security subnet with access only to SIEM, ticketing, and notification endpoints.
- Configure backup and disaster recovery by persisting triage state and playbook configurations to version-controlled repositories.
