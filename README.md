# LetsDefend SOC investigation portfolio

Practice investigations by Muhammad Awais Asgher. These are simulated training cases, not claims of production incident-response work.

| Case | Focus | Evidence limitations |
| --- | --- | --- |
| [SOC338: ClickFix / Lumma lure](Alerts/SOC338/Investigation.md) | Email triage, delivery versus execution, follow-up investigation | Endpoint execution is unconfirmed in the supplied material |
| [SOC342: SharePoint ToolShell](Alerts/SOC342/Investigation.md) | Web/endpoint correlation, extraction attempts, detection proposals | Raw telemetry and key-extraction output are not attached; token forgery is not demonstrated |

## Reading the reports

Distinguish reported lab observations, analyst interpretation, and unverified hypotheses. Proposed containment or remediation is not an action performed unless execution evidence is recorded. Detection queries are examples requiring local field mapping and testing.

New investigations should follow [the report template](REPORT_TEMPLATE.md): observation → evidence → interpretation → confidence → recommended response. Preserve timestamps and time zones, query time ranges, and evidence references where permitted. Do not invent missing telemetry or screenshots.

[LinkedIn](https://www.linkedin.com/in/awais-asgher-4882b8285/) · [License](LICENSE)
