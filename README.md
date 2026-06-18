# AIGuard T1

**A passive AI-traffic governance sensor for municipal and non-profit organization networks.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Debian%2012-informational)
![Status](https://img.shields.io/badge/status-production-success)

AIGuard T1 passively observes a mirrored copy of network traffic and produces a
governance-defensible record of artificial-intelligence service usage on an
organization's network. It was built to give resource-constrained organizations
- local governments and non-profits that cannot afford enterprise SASE/CASB
platforms - a practical, low-cost way to meet the AI-inventory and oversight
expectations of frameworks such as the **NIST AI Risk Management Framework**
(and, for public agencies, laws such as the **Texas Responsible AI Governance
Act, TRAIGA**).

It originated as a home-lab prototype, matured into a production system at a
municipal site, and is published here as a contribution to the local-government
and non-profit communities.

---

## Why this exists

There are roughly 19,500 mostly small and mid-size municipal governments in the
United States, and well over a million non-profit organizations. Both sectors
are chronically under-resourced in IT, both increasingly handle sensitive data
through AI-enabled tools, and both are largely priced out of commercial
AI-visibility tooling - SASE/CASB platforms typically cost $50,000–$200,000+ per
year.

Yet both carry real obligations to know what AI systems they operate: statutory
and policy obligations for public agencies, and donor-trust, grant-compliance,
and data-protection obligations for non-profits.

AIGuard T1 runs on a single repurposed workstation, carries no licensing cost,
and is configurable by an IT generalist without writing code.

---

## The detection philosophy: DNS-only

The core design decision in AIGuard T1 is **DNS-based detection**.

The intuitive approach — flagging traffic by destination IP range - fails in
modern cloud environments because AI providers share infrastructure with
general-purpose services. A single Microsoft IP range, for example, carries
Copilot, Teams, Outlook, and SharePoint traffic simultaneously; Google, AWS, and
Cloudflare ranges are equally shared. IP-based detection therefore produces very
high false-positive rates and is **not defensible for compliance or audit**.

AIGuard T1 instead keys detection on the **DNS resolution** that precedes a
connection. A query for a specific, unambiguous AI hostname (for example
`copilot.microsoft.com` or `claude.ai`) is evidence that a user or application
*intended* to reach that service - not merely that a packet reached shared cloud
infrastructure. This makes each detection an artifact you can defend in a
governance review.

> **DNS proves intent. IP only proves a packet reached shared infrastructure.**

### Known limits (by design, documented honestly)

DNS-only detection does not capture everything, and the tool does not pretend
otherwise:

- **Encrypted DNS (DoH/DoT)** bypasses passive interception unless managed
  endpoints are configured to use monitored resolvers.
- **AI embedded in a browser or application process** may reuse existing
  connections and generate no distinct DNS signature.
- **On-device AI** may generate no network traffic at all.

AIGuard reports *confirmed* AI service access. It is one tier of a layered
governance approach, not a complete inventory on its own.

---

## Features

- **AI provider detection** via DNS hostname resolution (with optional SNI
  correlation).
- **DLP scanning** of monitored traffic against configurable patterns.
- **Department / unit attribution** via VLAN mapping and Active Directory lookup.
- **Web dashboard** (FastAPI) with executive, operational, and historical views,
  filters, and CSV export.
- **Automated monthly reports** generated as DOCX for distinct audiences
  (IT, Legal/Compliance, Records, Executive).
- **MDR/SIEM integration** via syslog (e.g., Arctic Wolf), with optional
  severity-based filtering.
- **Policy classification** of detected tools as Authorized / Monitored / Shadow
  AI, mapped to your own AI governance policy through a single config file.

---

## Architecture

```
  Mirrored switch port (SPAN)
            │
            ▼
   ┌──────────────────┐      DNS / SNI       ┌──────────────────┐
   │  collector/      │  ───────────────────▶ │  SQLite event DB │
   │  capture.py      │      DLP analysis     │  (WAL mode)      │
   └──────────────────┘                       └──────────────────┘
            │                                          │
            │ syslog (optional)                        │
            ▼                                          ▼
   ┌──────────────────┐      ┌──────────────────┐   ┌──────────────────┐
   │  MDR / SIEM      │      │  dashboard/      │   │  reports/        │
   │  (Arctic Wolf)   │      │  FastAPI :8080   │   │  monthly DOCX    │
   └──────────────────┘      └──────────────────┘   └──────────────────┘
```

| Directory     | Purpose                                                        |
|---------------|----------------------------------------------------------------|
| `collector/`  | Passive packet capture, DNS/SNI detection, DLP, AD attribution. |
| `dashboard/`  | FastAPI web UI (3 tabs, filters, CSV export).                   |
| `reports/`    | Python + Node.js DOCX report generator and templates.          |

---

## Requirements

- Debian 12 (or comparable Linux) on a host with a capture interface receiving a
  SPAN/mirror of the segment to monitor.
- Python 3.11+ with `venv`.
- Node.js 20+ (for the DOCX report generator).
- Python packages: `scapy`, `fastapi`, `uvicorn`, `ldap3`, `pyyaml`
  (see `requirements.txt`).
- A switch port configured to mirror (SPAN) the traffic you intend to observe.

---

## Installation

```bash
# 1. Clone
git clone https://github.com/alfredo-gov/aiguard-t1.git
cd aiguard-t1

# 2. Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Node dependencies for the report generator
cd reports && npm install && cd ..

# 4. Create your configuration from the template
cp config.yaml.example config.yaml
#    then edit config.yaml for your environment (see below)
```

`config.yaml` is intentionally excluded from version control (see
`.gitignore`). Only the placeholder template `config.yaml.example` is published.

---

## Configuration

All environment-specific settings live in a single `config.yaml`. Copy the
example, then fill in the `YOUR_*` placeholders for your organization. The
example file documents every option inline. At minimum you will set:

- Organization name, division/unit, and branding.
- The capture interface and your network prefixes.
- Active Directory servers, domain, and a read-only service account (for
  department/unit attribution). *Optional — skip if you do not run AD.*
- Your VLAN → department/unit map.
- The AI hostnames to detect, grouped by provider and confidence tier.
- MDR/syslog destination (if used) and report recipients.

> **Note on traffic-classification thresholds.** The payload-size tiers in the
> example (keepalive / small event / active session / heavy session) are
> *empirically derived from observed traffic in a single production
> environment*. They are starting points, **not** industry standards. Re-baseline
> them against your own traffic before relying on them.

---

## Running

The collector and dashboard are designed to run as `systemd` services:

```bash
# Collector (passive capture + detection)
sudo systemctl enable --now aiguard-collector

# Dashboard (FastAPI on the configured port, default 8080)
sudo systemctl enable --now aiguard-dashboard
```

Reports are generated on a schedule (e.g., a monthly cron entry that runs the
report orchestrator). See `reports/` for the generator and templates.

---

## Roadmap

- **Tiered confidence model** — classify detections as *Confirmed*, *Probable*
  (AI-adjacent backends that also serve non-AI functions), or *General*
  infrastructure, rather than a binary AI / non-AI decision.
- Severity-based syslog filtering and digest batching for MDR integrations.
- Optional endpoint-level telemetry to cover AI that leaves no network signature.

---

## Contributing

Issues and pull requests are welcome. This project is aimed at the
local-government and non-profit communities; contributions that improve
portability, documentation, or detection accuracy for additional providers are
especially valued. Please do not include any organization-specific
configuration, internal addresses, or captured data in contributions.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

---

## Disclaimer

AIGuard T1 is a **passive** monitoring tool: it observes a mirror of traffic and
does not intercept, modify, or block it. It reports *confirmed* AI service
access and does not claim to produce a complete inventory of all AI activity.
Deploy it in accordance with your organization's policies and applicable law,
and ensure appropriate notice to users where required.
