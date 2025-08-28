# SMB Pentest Orchestrator — Build Cheatsheet

A terse, practical reference for building a one-command, low-noise SMB pen-test tool.

---

## Goals (anchor)

* **One command:** `pentest run engagement.yaml`
* **Safe by default:** passive → safe-active → optional intrusive.
* **Low noise:** curated templates/wordlists, strong dedupe.
* **Clear output:** Exec PDF, Tech HTML, JSON findings.
* **Deterministic:** version pinning + audit trail.

---

## Minimal Directory Layout

```
project/
  cmd/pentest/            # CLI entry
  internal/
    orchestrator/
    modules/              # nuclei, httpx, ffuf, etc. wrappers
    normalizer/
    reporter/
    store/                # sqlite/jsonl artifacts
  templates/              # nuclei bundle (pinned)
  lists/                  # tiny wordlists
  themes/                 # report HTML/CSS
  out/                    # run artifacts
  Makefile
  docker-compose.yml
```

---

## CLI UX (no prompts)

```
pentest run engagement.yaml \
  --out out/acme-2025-09 \
  --intrusive=false \
  --retest=out/last-findings.json \
  --quiet
```

**Subcommands:** `run`, `retest`, `validate`, `version`.

---

## `engagement.yaml` (example)

```yaml
name: "Acme SMB Light PT"
client: "Acme Co"
scope:
  targets: ["acme.example", "shop.acme.example"]
  include_ports: [80,443,8080,8443]
  max_hosts: 200
  allow_intrusive: false
  time_window:
    start: "2025-09-01T19:00:00Z"
    end:   "2025-09-02T06:00:00Z"
limits:
  rps_per_host: 2
  total_requests_per_host: 1000
  concurrency: 10
report:
  deliverables: [pdf_exec, html_tech, json_findings]
  redactions: true
  cvss: "v3.1"
  include_screenshots: true
notes:
  stack_hints: ["WordPress","Nginx","AWS"]
  contacts: ["it@acme.example"]
```

### YAML Validation (JSON Schema sketch)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["name","client","scope","limits","report"],
  "properties": {
    "scope": {
      "type": "object",
      "required": ["targets","allow_intrusive"],
      "properties": {
        "targets": {"type": "array", "items": {"type": "string"}},
        "include_ports": {"type": "array", "items": {"type": "integer"}},
        "max_hosts": {"type": "integer", "minimum": 1},
        "allow_intrusive": {"type": "boolean"}
      }
    }
  }
}
```

---

## Safe Defaults

* RPS: **2/host** (burst 4). Max **1000 req/host**.
* Timeouts: connect 5s, read 10s, **2 retries** w/ exponential backoff.
* Ports: top 100 TCP; include 80,443,8080,8443.
* User-Agent: distinct per module; honor `robots.txt` for passive pulls.
* Intrusive modules OFF unless `allow_intrusive: true` **and** `--intrusive=true`.

---

## Pipeline (inputs → outputs)

1. **Seed/Guardrails** → scope-normalized targets (A/AAAA/CNAME resolved).
2. **Discovery**: `subfinder`(passive) → `dnsx` (A/AAAA/CNAME) → host list.
3. **Ports/Services**: `naabu` (top100) → `nmap -sV -sC` on alive.
4. **HTTP Sweep**: `httpx` (status/title/headers/tech/body-hash) → `gowitness` screenshots.
5. **Quick Risks**:

   * `nuclei` (allowlist packs): headers, misconfig, panels, sensitive-files, tech CVEs, TLS.
   * `ffuf` tiny wordlist (tech-aware extensions).
   * `testssl.sh` (grade, expiry, weak suites).
6. **Auto-Gated (optional)**:

   * `dalfox` on reflectable params only (budgeted).
   * `sqlmap` on ≤3 candidates (3 min total; `--risk=1 --level=1 --technique=T`).
7. **Normalize & Dedupe** → unified findings list.
8. **Score & Prioritize** → CVSS + quick-fix ranking.
9. **Render** → PDF Exec, HTML Tech, JSON findings.

---

## Module Interface (pseudo)

```python
class Module:
    name: str
    def run(self, scope: ScopeCtx) -> list[RawFinding]: ...

# Orchestrator order
modules = [Subfinder(), Dnsx(), Naabu(), Nmap(), Httpx(), Gowitness(),
           NucleiAllowlist(), FfufTiny(), TestSSL(), OptionalDalfox(), OptionalSqlmap()]
```

**RawFinding → NormalizedFinding** via `normalizer.map(tool_output)`.

---

## Intrusive Gating Logic

```python
def intrusive_allowed(cfg, candidate_score):
    return (
      cfg.scope.allow_intrusive and cfg.flags.intrusive and
      candidate_score >= 0.7 and within_time_window(cfg)
    )
```

Candidate score example: URL parameter reflectivity + error patterns + tech match.

---

## Finding Schema (normalized)

```json
{
  "id": "webdir-7f1c2a9",
  "target": "https://shop.acme.example",
  "asset": {"host":"shop.acme.example","ip":"203.0.113.5","port":443,"service":"https"},
  "category": "Exposure",
  "title": "Backup archive accessible",
  "severity": "High",
  "cwe": "CWE-200",
  "cvss_v3": 7.5,
  "evidence": {
    "request": "GET /backup.zip",
    "response_status": 200,
    "response_snippet": "PK\u0003\u0004...",
    "screenshot": "artifacts/shop/backup.png"
  },
  "repro_steps": ["Visit /backup.zip", "Observe HTTP 200 download."],
  "remediation": ["Remove backup from webroot.", "Block via server config."] ,
  "confidence": "High",
  "tool": "ffuf+httpx",
  "timestamp": "2025-09-01T20:11:05Z"
}
```

---

## Artifacts Layout

```
out/<run-id>/
  findings.json
  report-exec.pdf
  report-tech.html
  artifacts/
    screenshots/
    bodies/           # redacted; size cap
  logs/
    httpx.jsonl
    nuclei.jsonl
    ffuf.jsonl
    testssl.jsonl
  versions/
    tools.json        # exact versions/commits
```

---

## Nuclei Allowlist (ship pinned bundle)

* Categories: `security-headers`, `misconfiguration`, `exposed-panels`, `sensitive-files`, `ssl`, `cves/<top-techs>`.
* Maintain **monthly** pack: `templates-YYYY-MM` + SHA256.
* Disable templates with destructive actions; run with `-severity low,medium,high,critical`.

---

## Tiny Wordlists (≤100 entries)

`lists/tiny-web.txt` (seed):

```
admin
login
backup
backups
.old
.bak
.git/
env
config
config.php
phpinfo.php
robots.txt
sitemap.xml
swagger
api
console
setup
installer
phpmyadmin
server-status
server-info
uploads
static
vendor
composer.json
package.json
.yarnrc
.vscode
.idea
```

**Tech-aware extensions auto-added**: `.php`, `.aspx`, `.jsp`, `.bak`, `.zip` based on detected stack.

---

## Scoring & Prioritization

* Compute CVSS v3.1; include EPSS/KEV flags if available (optional passive).
* Add **Fix Effort** tag (Low/Med/High) → prioritize **High risk + Low effort** first.

---

## Reporting

**Exec PDF (2–3 pages)**

* Summary, Top 5, Business impact, Next steps, Trend vs last run.

**Tech HTML (full)**

* Per finding: Description, Evidence, Impact, Affected assets, Repro, Fix, References.
* Anchors + copy buttons; link to artifacts.

**JSON**

* Machine-readable for ticketing.

---

## Logging (JSONL)

* One line per event/finding; fields: `ts, module, target, action, status, latency_ms, notes`.
* Redact secrets/cookies; cap body size.

---

## WAF & Backoff

* Detect 403/429/5xx spikes, JS challenges; **auto-throttle** or pause module.
* Switch to passive-only if persistent blocking.

---

## Error Handling

* Retries: 2 (idempotent ops only).
* Per-module time budget; fail-soft (continue others).
* Exit codes: `0 ok`, `2 partial`, `3 blocked`, `4 config error`.

---

## Retest Mode

* Input: `findings.json` from prior run.
* Recheck only affected assets/paths; mark `fixed`/`still_vulnerable`.
* Output delta table in both reports.

---

## Integrations (optional)

* Webhooks (Slack/Teams): Top 5 + artifact links.
* Ticketing (Jira/GitHub/GitLab): create issues from JSON.

---

## Version Pinning

* Store exact versions/SHAs of tools & template pack in `versions/tools.json`.
* Render matrix in report appendix.

---

## Makefile Targets

```
make build       # compile binary
make lint test   # run linters & unit tests
make run         # dev run with sample engagement
make pack        # bundle templates/lists
```

---

## Docker Compose (dev)

```yaml
services:
  pentest:
    build: .
    network_mode: host   # careful; for lab/VPN only
    volumes:
      - ./out:/app/out
      - ./lists:/app/lists
      - ./templates:/app/templates
    command: ["pentest","run","/app/engagement.yaml","--out","/app/out"]
```

---

## Test Checklist (v1)

* [ ] Scope guardrails enforced
* [ ] RPS/timeout limits respected
* [ ] Nuclei allowlist only
* [ ] Dedupe merges across modules
* [ ] Reports render with screenshots & redactions
* [ ] Retest shows fixed/still vulnerable
* [ ] Versions/commit matrix captured

---

## Quick Pseudo-Orchestrator

```python
def run(cfg):
  ctx = load(cfg); enforce_guardrails(ctx)
  hosts = subfinder(ctx) | dnsx(ctx)
  alive = naabu(hosts, ctx); services = nmap(alive, ctx)
  http_targets = httpx(services, ctx); screenshots = gowitness(http_targets)
  findings = nuclei(http_targets) + ffuf(http_targets) + testssl(alive)
  if intrusive_allowed(ctx, candidate_score=0.7):
      findings += dalfox(http_targets)
      findings += sqlmap(http_targets)
  findings = normalize_dedupe(findings); score(findings)
  render_reports(findings, ctx)
```

---

**Tip:** keep modules pure (input → output), keep state in store, and keep defaults conservative. This stays one-command forever.

