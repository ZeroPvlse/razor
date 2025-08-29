<p align="center">
  <img src="razor_logo.jpg" alt="Razor Logo" width="280"/>
</p>

<h1 align="center">Razor</h1>
<h3 align="center">Rapid Assessment Zero-Noise Ops Runner</h3>

<p align="center">
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.22+-blue?logo=go" alt="Go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/ZeroPvlse/razor/actions"><img src="https://img.shields.io/github/actions/workflow/status/ZeroPvlse/razor/go.yml?branch=main" alt="Build Status"></a>
  <a href="https://github.com/ZeroPvlse/razor/releases"><img src="https://img.shields.io/github/v/release/ZeroPvlse/razor?color=orange" alt="Release"></a>
</p>

---

## Overview

**Razor** is an open-source CLI tool for penetration testers and security engineers.  
It simplifies engagement setup by letting you define scope, rules, and output in a single `.yaml` config.  

Instead of juggling scripts and ad-hoc notes, Razor enforces repeatable, low-noise assessments:  

- Generate a clean config template.  
- Fill in scope, limits, and reporting preferences.  
- Run Razor with that config to execute the engagement.  
- Reuse configs across projects with only minimal edits.  

---

## Installation

```bash
# Clone the repo
git clone https://github.com/ZeroPvlse/razor.git
cd razor

# Build (requires Go 1.22+)
go build -o razor ./cmd/razor

# Optional: move binary to PATH
mv razor /usr/local/bin/
````

---

## Usage

### 1. Generate a config template

```bash
razor --gen engagement.yaml
```

### 2. Edit the config

Fill in details for your engagement:

```yaml
name: ""              
client: ""           
scope:
  targets: ["", ""]
  include_ports: []
  max_hosts: 0
  allow_intrusive: false
  time_window:
    start: ""
    end: ""
limits:
  rps_per_host: 2
  total_requests_per_host: 1000
  concurrency: 10
  connect_timeout_s: 5
  request_timeout_s: 10
  retries: 2
report:
  deliverables: []
  redactions: true
  cvss: "v3.1"
  include_screenshots: true
  out_dir: ""
notes:
  stack_hints: []
  contacts: []
  tags: []
```

### 3. Run Razor with your config

```bash
razor --run engagement.yaml
```

---

## 📑 Config Reference

| Section    | Key                       | Description                                                                  |
| ---------- | ------------------------- | ---------------------------------------------------------------------------- |
| **meta**   | `name` / `client`         | Engagement name + client identifier.                                         |
| **scope**  | `targets`                 | Explicit list of domains/IPs/CIDRs in-scope. Nothing else will be touched.   |
|            | `include_ports`           | Optional port whitelist. Empty = safe defaults.                              |
|            | `max_hosts`               | Cap the number of hosts considered "key" findings (0 = unlimited).           |
|            | `allow_intrusive`         | Enables heavier checks (SQLi, XSS, etc.). Requires explicit client approval. |
|            | `time_window`             | Restrict tests to off-hours in UTC.                                          |
| **limits** | `rps_per_host`            | Requests per second per host.                                                |
|            | `total_requests_per_host` | Hard cap of requests per host. Prevents accidental DoS.                      |
|            | `concurrency`             | Parallelism: higher = faster/noisier. Lower = slower/stealthier.             |
|            | `connect_timeout_s`       | TCP connect timeout.                                                         |
|            | `request_timeout_s`       | HTTP request timeout.                                                        |
|            | `retries`                 | Retry count for flaky endpoints.                                             |
| **report** | `deliverables`            | Output formats: `pdf_exec`, `html_tech`, `json_findings`.                    |
|            | `redactions`              | Redact sensitive data in logs/screens.                                       |
|            | `cvss`                    | Severity scoring flavor. Default = v3.1.                                     |
|            | `include_screenshots`     | Capture screenshots for findings.                                            |
|            | `out_dir`                 | Output directory.                                                            |
| **notes**  | `stack_hints`             | Tech stack hints (`WordPress`, `AWS`, `Nginx`, etc.).                        |
|            | `contacts`                | Stakeholder emails/chat handles.                                             |
|            | `tags`                    | Engagement labels (`prod`, `EU`, etc.).                                      |

---

## Deliverables

Depending on your config, Razor can generate:

* **Executive Summary (PDF)** – High-level findings for non-technical stakeholders.
* **Technical Report (HTML)** – Detailed vulnerabilities and evidence.
* **Machine-Readable Findings (JSON)** – For automation, dashboards, or pipelines.

---

## Principles

* **Zero Noise** – Stays within explicit scope. No accidental spray-and-pray scans.
* **Client-First** – Config enforces client approvals (intrusive testing, time windows).
* **Safety Nets** – Rate limits, retries, and caps prevent accidental outages.
* **Repeatability** – Engagements can be replayed, audited, and versioned.

---

## Contributing

Razor is developed by **ZeroPvlse** for the security community.
Pull requests, bug reports, and feature suggestions are welcome.

---

## Disclaimer

Razor is for **authorized penetration testing and security research only**.
You must obtain **explicit written permission** before using it against any system.
The authors are not responsible for misuse or damages caused by this tool.



