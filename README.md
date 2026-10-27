<div align="center">

# Insyte

### Passive Exposure Intelligence

**See what the public Internet already knows about a target — and correlate it into one evidence-backed attack-surface graph.**

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](#technology-stack)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688?logo=fastapi&logoColor=white)](#technology-stack)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](#technology-stack)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](#technology-stack)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](#quickstart-docker)
[![Tests](https://img.shields.io/badge/backend_tests-180_passing-brightgreen)](#testing-and-quality)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[Quickstart](#quickstart-docker) · [Features](#what-insyte-does) · [Architecture](#architecture) · [Configuration](#configuration) · [API](#api-reference) · [Security](#security-model) · [Troubleshooting](#troubleshooting)

</div>

---

> **Authorized use only.** Insyte is an intelligence-collection and correlation
> platform. It does not exploit, authenticate, brute-force, fuzz, or validate
> discovered credentials. Use it only against domains and IP addresses you own
> or have explicit written permission to assess.

## Table of contents

- [Overview](#overview)
- [Screenshots](#screenshots)
- [What Insyte does](#what-insyte-does)
  - [Collection modes](#collection-modes)
  - [Intelligence modules](#intelligence-modules-29)
  - [External providers](#external-providers-32)
  - [Correlation and scoring](#correlation-and-scoring)
  - [Reporting](#reporting)
  - [Accounts, credentials, and schedules](#accounts-credentials-and-schedules)
- [Architecture](#architecture)
  - [Technology stack](#technology-stack)
  - [Services](#services)
  - [Scan lifecycle](#scan-lifecycle)
- [Quickstart (Docker)](#quickstart-docker)
- [Configuration](#configuration)
  - [Environment variables](#environment-variables)
  - [Optional provider keys](#optional-provider-keys)
  - [Secrets and SECRET_KEY](#secrets-and-secret_key)
- [Usage guide](#usage-guide)
  - [Create the first account](#create-the-first-account)
  - [Run a scan](#run-a-scan)
  - [Explore results](#explore-results)
  - [Download reports](#download-reports)
  - [Scheduled scans](#scheduled-scans)
  - [Per-account provider credentials](#per-account-provider-credentials)
- [Local development](#local-development)
- [API reference](#api-reference)
- [Data model](#data-model)
- [Security model](#security-model)
- [Testing and quality](#testing-and-quality)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Insyte is a self-hosted cybersecurity intelligence platform focused on **deep
passive reconnaissance** and **public-information correlation**. It does not
simply enumerate a domain. It correlates publicly observable infrastructure,
URLs, APIs, JavaScript, certificates, technologies, cloud assets, historical
observations, and indexed exposures into a single evidence-backed
attack-surface intelligence graph.

Enter a domain, IPv4 address, or IPv6 address, choose a collection mode, and run
intelligence. Every scan is a single on-demand run tied to your account. Insyte
has JWT authentication with per-user accounts, and each user can store their
own provider API keys — encrypted at rest — under **Settings → Credentials**.

**Highlights**

- **Zero API keys required.** The core platform is fully functional out of the
  box. A provider without a key reports itself unavailable and the scan
  continues; modules that would be useless without a key skip visibly with a
  reason instead of pretending to succeed.
- **Evidence, not guesses.** Every asset carries per-source provenance and a
  confidence score derived from source reliability and corroboration.
- **Version-range CVE matching.** Detected technologies are matched against NVD
  CVE configurations by vendor:product and affected version range — not by
  keyword guesswork. Weak evidence is labelled explicitly.
- **Secrets are never stored in full.** Secret-shaped values found in
  JavaScript are persisted only as a masked preview plus a SHA-256 digest.
- **Read-only by construction.** No module can construct its own HTTP client or
  send anything other than GET/HEAD. SSRF protection is enforced on every
  outbound request, including every redirect hop.
- **Reproducible deployment.** One `docker compose up --build` starts
  PostgreSQL, Redis, the API, Celery workers, the scheduler, and the frontend;
  migrations run automatically.
- **No telemetry, no phone-home.** The only outbound traffic is the intelligence
  collection you explicitly request.

---

## Screenshots

| Overview | Scan results |
|---|---|
| ![Insyte overview](docs/screenshots/02-overview.png) | ![Insyte scan results](docs/screenshots/03-scan-overview.png) |

| Findings | Asset graph |
|---|---|
| ![Insyte findings](docs/screenshots/04-findings.png) | ![Insyte asset graph](docs/screenshots/05-asset-graph.png) |

> The example screenshots show a passive scan of `example.com` with no optional
> provider keys configured. The **Partial** status is expected: two key-gated
> modules skipped, and one network-intelligence module failed because the host
> environment resolved a provider through a NAT64 prefix that the SSRF guard
> correctly refuses. See [Troubleshooting](#troubleshooting).

---

## What Insyte does

### Collection modes

| Mode | What it collects | What it never does |
|---|---|---|
| **Passive Intelligence** | Certificate Transparency, RDAP, passive DNS, archives, public datasets, and at most one read-only GET per well-known resource on the target itself (homepage, `robots.txt`, `sitemap.xml`, `.well-known/*`). | No crawling, no brute force, no fuzzing, no port scanning, no exploitation, no repeated requests. |
| **Web Surface Collection** | Everything in Passive, plus an opt-in same-origin crawl of publicly linked pages and the JavaScript/CSS they reference, within explicit page, URL, and file budgets. | No POST/PUT/PATCH/DELETE, no form submission, no authentication, no brute force, no fuzzing, no port scanning. |

Both modes are strictly read-only. Web Surface Collection only retrieves URLs
that are already linked from content the target serves publicly.

### Intelligence modules (29)

Modules declare their supported modes, dependencies, credential requirements,
and timeouts. Independent modules run concurrently in dependency waves; a
failed module never takes down the scan.

| # | Module ID | Name | Category | Modes | Needs key |
|---:|---|---|---|---|---|
| 1 | `domain_intelligence` | Domain Intelligence | Core | Passive, Web | No |
| 2 | `dns_intelligence` | DNS Intelligence | Core | Passive, Web | No |
| 3 | `email_security` | Email Security Intelligence | Core | Passive, Web | No |
| 4 | `typosquat` | Typosquat Discovery | Core | Passive | No |
| 5 | `subdomain_takeover` | Subdomain Takeover Risk | Core | Passive | No |
| 6 | `certificate_intelligence` | Certificate Intelligence | Core | Passive, Web | No |
| 7 | `threat_intelligence` | Threat Intelligence | External | Passive | No |
| 8 | `subdomain_intelligence` | Subdomain Intelligence | Core | Passive, Web | No |
| 9 | `historical_intelligence` | Historical Web Intelligence | Historical | Passive, Web | No |
| 10 | `email_osint` | Email OSINT | Core | Passive, Web | Yes |
| 11 | `social_footprint` | Social Footprint | Core | Passive, Web | No |
| 12 | `github_intelligence` | GitHub Intelligence | External | Passive, Web | No |
| 13 | `ip_asn_intelligence` | IP / ASN Intelligence | Core | Passive, Web | No |
| 14 | `cloud_detection` | Cloud Intelligence | Core | Passive, Web | No |
| 15 | `corporate_intelligence` | Corporate Intelligence | Core | Passive, Web | No |
| 16 | `web_surface` | Homepage & Well-Known Resources | Core | Passive, Web | No |
| 17 | `favicon_intelligence` | Favicon Fingerprinting | Web Surface | Passive, Web | No |
| 18 | `technology_intelligence` | Technology Intelligence | Core | Passive, Web | No |
| 19 | `security_headers` | Security Header Intelligence | Core | Passive, Web | No |
| 20 | `waf_cdn_intelligence` | WAF / CDN / Edge Intelligence | Web Surface | Passive, Web | No |
| 21 | `javascript_intelligence` | JavaScript Intelligence | Web Surface | Web only | No |
| 22 | `url_collection` | URL Intelligence | Web Surface | Web only | No |
| 23 | `api_discovery` | API Discovery Engine | Web Surface | Web only | No |
| 24 | `source_map_intelligence` | Source Map Intelligence | Web Surface | Web only | No |
| 25 | `robots_sitemap_intelligence` | Robots.txt & Sitemap Intelligence | Exposure | Passive, Web | No |
| 26 | `indexed_exposure` | Indexed Exposure Intelligence | Exposure | Passive, Web | No |
| 27 | `document_intelligence` | Document Intelligence | Web Surface | Passive, Web | No |
| 28 | `google_dorking` | Google Dorking | Exposure | Passive, Web | Yes |
| 29 | `wayback_diff` | Wayback Snapshot Diff | Historical | Passive | No |

`email_osint` requires Hunter.io and/or HIBP; `google_dorking` requires a Google
Programmable Search API key and search-engine ID. Without those keys the modules
skip with an explicit reason.

### External providers (32)

Every provider is optional. The platform starts and scans with all of them left
blank. Public, unauthenticated providers are used automatically; key-gated
providers become available when a key is supplied through the environment or
per-account credentials.

**Public / unauthenticated**

| Provider ID | Name | Purpose |
|---|---|---|
| `crtsh` | crt.sh | Certificate Transparency |
| `certspotter` | Cert Spotter | Certificate Transparency |
| `hackertarget` | HackerTarget | Passive host search |
| `rapiddns` | RapidDNS | Subdomain dataset |
| `otx` | AlienVault OTX | Passive DNS / threat intel |
| `wayback` | Wayback Machine | Historical URLs |
| `commoncrawl` | Common Crawl | Historical index |
| `urlscan` | urlscan.io | Public scan archive |
| `rdap` | RDAP | Registration data |
| `ripestat` | RIPEstat | Network registration |
| `bgp_origin` | bortzmeyer.org | BGP origin |
| `grepapp` | grep.app | Public code search |
| `nvd` | NVD | CVE data |
| `epss` | EPSS | Exploit prediction |
| `kev` | CISA KEV | Known exploited vulnerabilities |
| `greynoise` | GreyNoise Community | IP reputation |
| `threatfox` | ThreatFox | IOC matching |
| `urlhaus` | URLhaus | Malware URL matching |
| `sec_edgar` | SEC EDGAR | Corporate filings |
| `wikidata` | Wikidata | Corporate metadata |

**Key-gated**

| Provider ID | Name | Key / env var | Free tier |
|---|---|---|---|
| `virustotal` | VirusTotal | `VIRUSTOTAL_API_KEY` | Free public API, rate-limited |
| `shodan` | Shodan | `SHODAN_API_KEY` | Free membership covers host lookups |
| `censys` | Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | 250 queries/month |
| `securitytrails` | SecurityTrails | `SECURITYTRAILS_API_KEY` | 50 queries/month |
| `github` | GitHub | `GITHUB_TOKEN` | Free read-only PAT |
| `abuseipdb` | AbuseIPDB | `ABUSEIPDB_API_KEY` | 1,000 checks/day |
| `chaos` | ProjectDiscovery Chaos | `CHAOS_API_KEY` | Generous free subdomain quota |
| `opencorporates` | OpenCorporates | `OPENCORPORATES_API_TOKEN` | Free registration token |
| `grayhatwarfare` | GrayhatWarfare | `GRAYHATWARFARE_API_KEY` | Free "Registered" tier |
| `hibp` | Have I Been Pwned | `HIBP_API_KEY` | Paid only |
| `hunterio` | Hunter.io | `HUNTER_API_KEY` | 25 searches/month |
| `google_cse` | Google Programmable Search | `GOOGLE_CSE_API_KEY` + `GOOGLE_CSE_CX` | 100 queries/day |

Optional keys that raise limits but are not required: `URLSCAN_API_KEY`,
`OTX_API_KEY`, `GREYNOISE_API_KEY`, `NVD_API_KEY`.

### Correlation and scoring

1. **Merge** — observations from every module and provider are deduplicated by
   normalized asset identity.
2. **Provenance** — each asset keeps every source that reported it.
3. **Confidence** — source reliability and corroboration produce a 0–100 score.
4. **Graph** — domains, subdomains, IPs, ASNs, certificates, technologies, URLs,
   APIs, and JavaScript artifacts are linked with typed relationships.
5. **Risk** — severity, confidence, exposure level, asset importance, and
   corroboration produce Insyte's own **Exposure Score (0–100)**. This is
   intentionally distinct from CVSS, which is reproduced verbatim from its
   source and never recomputed.
6. **CVE correlation** — NVD configurations are matched by vendor:product and
   version range. A CVE is `definitive` only when the detected version clears a
   configurable confidence floor; everything else is recorded as
   *"potentially affected — version confidence insufficient for definitive
   mapping"*. EPSS probability and CISA KEV membership are layered on top.

### Reporting

Every completed or partially completed scan can be exported as:

- **PDF** — 24-section report with charts, tables, findings, CVE correlation,
  recommendations, and a module appendix.
- **Markdown** — the same structure as portable text.
- **JSON** — the complete machine-readable report payload.

Reports are generated once, stored on the `insyte_reports` volume, and served
from disk. Filenames are derived from a report UUID and a sanitized target slug,
never from a raw request-controlled string.

### Accounts, credentials, and schedules

- **Accounts** — email + password registration, JWT bearer sessions. Passwords
  are hashed with scrypt; tokens are HS256 JWTs signed with `SECRET_KEY`.
- **Per-user ownership** — scans, schedules, projects, and credentials are
  owner-scoped. Another account's resource reads as `404`, never `403`.
- **Per-account provider keys** — stored encrypted at rest with Fernet
  (AES-128-CBC + HMAC), keyed from `SECRET_KEY`. The UI shows only a masked hint.
  A user key overrides the deployment's environment default for that scan.
- **Schedules** — create a recurrence policy for a target with an interval from
  1 hour to 30 days. Celery Beat dispatches due schedules every 5 minutes. After
  a scheduled scan, Insyte diffs it against the previous completed scan and
  stores added/removed/changed counts plus new finding titles.
- **Scan diffing** — compare any two scans of the same target under **Changes**.

---

## Architecture

```text
                              Browser
                                 │
                    ┌────────────▼────────────┐
                    │   Frontend (SSR)        │
                    │   TanStack Start/React  │
                    │   :5173 → :3000         │
                    └────────────┬────────────┘
                                 │ REST / JSON
                    ┌────────────▼────────────┐
                    │   FastAPI API           │
                    │   auth, routing,        │
                    │   reports, validation   │
                    │   :8000                 │
                    └───┬──────────┬──────────┘
                        │          │
          ┌─────────────▼──┐   ┌───▼─────────────┐
          │  PostgreSQL 16 │   │   Redis 7       │
          │  JSONB, UUID   │   │ cache + broker  │
          │  25 tables     │   │                 │
          └────────────────┘   └───┬─────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Celery worker(s)            │
                    │  scan orchestrator           │
                    │  dependency waves + threads  │
                    └──────┬─────────────┬─────────┘
                           │             │
              ┌────────────▼───┐   ┌─────▼──────────────┐
              │ 29 modules     │   │ 32 provider adapters│
              │ passive / web  │   │ CT, DNS, CVE,       │
              │ historical /   │   │ archives, OSINT,    │
              │ external       │   │ threat intel        │
              └───────┬────────┘   └─────┬───────────────┘
                      │                  │
              ┌───────▼──────────────────▼───────┐
              │  SSRF-guarded HTTP client         │
              │  resolve → validate → pin → fetch │
              │  GET/HEAD only, byte-capped       │
              └───────────────┬───────────────────┘
                              │
              ┌───────────────▼───────────────────┐
              │  Correlation → confidence → graph │
              │  → risk score → CVE correlation   │
              └───────────────┬───────────────────┘
                              │
              ┌───────────────▼───────────────────┐
              │  Report engine: PDF / MD / JSON   │
              └───────────────────────────────────┘
```

### Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, SQLAlchemy 2.x, Pydantic 2, Alembic |
| Async / jobs | Celery 5, Redis 7 |
| Database | PostgreSQL 16 (JSONB, native UUID) |
| Collection | httpx, dnspython, cryptography, BeautifulSoup, lxml |
| Reporting | ReportLab |
| Frontend | React 19, TanStack Start, TanStack Router, TanStack Query |
| UI | Tailwind CSS v4, Radix UI / shadcn/ui, lucide-react, Recharts, d3-force |
| Runtime | Docker Compose (6 services) |

### Services

| Service | Container | Host port | Purpose |
|---|---|---|---|
| `postgres` | `insyte-postgres` | internal only | Persistent database |
| `redis` | `insyte-redis` | internal only | Cache, Celery broker, results backend |
| `api` | `insyte-api` | `8000` | FastAPI, migrations on startup |
| `worker` | compose-generated | internal only | Celery scan/report workers |
| `beat` | `insyte-beat` | internal only | Schedule dispatcher (exactly one replica) |
| `frontend` | `insyte-frontend` | `5173` | SSR frontend |

### Scan lifecycle

1. Client `POST /api/scans` with `target`, `mode`, and optional `modules`.
2. The API validates the target, resolves modules, creates a `queued` scan, and
   dispatches `insyte.run_scan` to Celery.
3. A worker installs the owner's decrypted provider credentials, builds
   dependency waves, and executes modules concurrently.
4. Every module result is persisted with `completed`, `skipped`, or `failed`
   status and an explicit reason.
5. Correlation merges assets, computes confidence, builds the graph, scores
   exposure, and correlates CVEs.
6. Status becomes `completed` or `partial`; reports can be generated on demand.
7. Reads reap orphaned scans if no worker ever picked them up, so the UI never
   shows a permanently "scanning" row without explanation.

---

## Quickstart (Docker)

### Prerequisites

- Docker Engine 24+ with the Compose v2 plugin
- ~4 GB free RAM (more for concurrent scans)
- Ports **5173** and **8000** free on the host
- Outbound HTTPS from the containers (for public intelligence sources)

### Start

```bash
git clone https://github.com/ishant-g/insyte.git
cd insyte

cp .env.example .env
# Optional: edit .env — set SECRET_KEY and any provider API keys.

docker compose up --build -d
```

The first build takes a few minutes. Migrations run automatically when the API
container starts.

### Verify

```bash
docker compose ps
curl -s http://localhost:8000/health
```

Healthy output:

```json
{"status":"ok","app":"Insyte","version":"1.0.0","database":true,"redis":true,"worker_alive":true,"worker_count":1}
```

`worker_alive` can remain `false` for up to ~30 seconds after startup because
liveness results are cached briefly.

### Open

| Interface | URL |
|---|---|
| Web UI | <http://localhost:5173> |
| API | <http://localhost:8000> |
| OpenAPI / Swagger | <http://localhost:8000/docs> |
| ReDoc | <http://localhost:8000/redoc> |

Create the first account at <http://localhost:5173/register>. There is no
default or seeded account. Registration can be closed later with
`ALLOW_REGISTRATION=false`.

### Stop / reset

```bash
docker compose down          # stop, keep data
docker compose down -v       # stop and delete database/report volumes
```

---

## Configuration

All configuration is environment-driven. Copy `.env.example` to `.env`; Compose
passes it to the API, worker, and beat containers. The frontend API URL is a
build-time argument because Vite inlines it into the client bundle.

### Environment variables

#### Application

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `Insyte` | Display name |
| `APP_VERSION` | `1.0.0` | Version reported by the API |
| `ENVIRONMENT` | `development` | `development`, `staging`, or `production` |
| `DEBUG` | `false` | FastAPI debug mode; never enable in production |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `LOG_FORMAT` | `json` | `json` or `console` |
| `HOST` | `0.0.0.0` | API bind address inside the container |
| `PORT` | `8000` | API port inside the container |
| `API_PREFIX` | `/api` | Prefix for all routes except `/health` |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | Exact allowed browser origins; never `*` |
| `ENABLE_HSTS` | `false` | Enable only when served over HTTPS |

#### Authentication

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `insyte-dev-secret-change-me` | Signs JWTs and derives the credential-encryption key. **Change for any shared deployment.** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `10080` (7 days) | Session lifetime |
| `ALLOW_REGISTRATION` | `true` | Set `false` to close self-service registration |

#### Database / queue

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://insyte:insyte@postgres:5432/insyte` | PostgreSQL DSN (PostgreSQL is required in production) |
| `POSTGRES_USER` | `insyte` | Compose-managed database user |
| `POSTGRES_PASSWORD` | `insyte` | Compose-managed database password |
| `POSTGRES_DB` | `insyte` | Compose-managed database name |
| `REDIS_URL` | `redis://redis:6379/0` | Cache |
| `CELERY_BROKER_URL` | `redis://redis:6379/1` | Task broker |
| `CELERY_RESULT_BACKEND` | `redis://redis:6379/2` | Task results |
| `CELERY_TASK_ALWAYS_EAGER` | `false` | Run tasks inline; only for tests/local debugging |

#### Collection limits

| Variable | Default | Description |
|---|---|---|
| `HTTP_CONNECT_TIMEOUT` | `5.0` | TCP/TLS connect timeout (seconds) |
| `HTTP_READ_TIMEOUT` | `10.0` | Read timeout (seconds) |
| `HTTP_TOTAL_TIMEOUT` | `20.0` | Total request deadline (seconds) |
| `HTTP_MAX_REDIRECTS` | `3` | Redirect hops; every hop is re-validated |
| `HTTP_MAX_RESPONSE_BYTES` | `5242880` | Global response cap (5 MiB) |
| `HTTP_MAX_CONCURRENCY` | `6` | Concurrent outbound requests per scan |
| `MAX_URLS_PER_SCAN` | `5000` | URL budget |
| `MAX_JS_FILES_PER_SCAN` | `60` | JavaScript file budget |
| `MAX_PAGES_PER_SCAN` | `25` | Crawled page budget |
| `MAX_SUBDOMAINS_PER_SCAN` | `5000` | Subdomain budget |
| `MAX_SITEMAP_DEPTH` | `3` | Sitemap recursion depth |
| `MAX_SITEMAP_URLS` | `2000` | Sitemap URL cap |
| `MAX_HISTORICAL_URLS` | `5000` | Historical URL cap |

#### Scan and worker limits

| Variable | Default | Description |
|---|---|---|
| `SCAN_TIME_LIMIT` | `1800` | Hard scan ceiling (seconds) |
| `SCAN_SOFT_TIME_LIMIT` | `1680` | Soft limit for graceful failure |
| `MODULE_TIME_LIMIT` | `300` | Per-module ceiling (seconds) |
| `SCAN_PICKUP_TIMEOUT` | `180` | Reap scans never picked up by a worker |
| `DNS_RESOLVE_TIMEOUT` | `8.0` | SSRF-guard DNS deadline |
| `ALLOW_PRIVATE_TARGETS` | `false` | Test-only escape hatch; keep false |
| `BLOCKED_HOSTS` | *(empty)* | Extra hostnames the SSRF guard must refuse |
| `CACHE_ENABLED` | `true` | Enable Redis-backed caching |
| `CACHE_TTL_DNS` | `300` | DNS cache TTL |
| `CACHE_TTL_PROVIDER` | `3600` | Provider cache TTL |
| `CACHE_TTL_HISTORICAL` | `21600` | Historical-source cache TTL |

#### Reports

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `/var/lib/insyte` | Report/artifact storage root |
| `REPORT_RETENTION_DAYS` | `30` | Retention value surfaced in effective settings |

#### CVE intelligence

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | *(empty)* | Raises NVD rate limits |
| `CVE_LOOKUP_ENABLED` | `true` | Enable CVE correlation |
| `CVE_MIN_VERSION_CONFIDENCE` | `70` | Floor for a `definitive` version match |

#### Frontend (Compose build)

| Variable | Default | Description |
|---|---|---|
| `INSYTE_PUBLIC_API_URL` | `http://localhost:8000` | Browser-facing API URL baked into the frontend build |
| `VITE_API_URL` | `http://localhost:8000` | Frontend source default for local development |

### Optional provider keys

Add keys either to `.env` (deployment-wide defaults) or per account under
**Settings → Credentials** in the UI (encrypted per user, and taking precedence
for that user's scans).

- `VIRUSTOTAL_API_KEY`
- `SHODAN_API_KEY`
- `CENSYS_API_ID` + `CENSYS_API_SECRET`
- `SECURITYTRAILS_API_KEY`
- `GITHUB_TOKEN`
- `URLSCAN_API_KEY`
- `OTX_API_KEY`
- `ABUSEIPDB_API_KEY`
- `CHAOS_API_KEY`
- `GRAYHATWARFARE_API_KEY`
- `GREYNOISE_API_KEY`
- `OPENCORPORATES_API_TOKEN`
- `HIBP_API_KEY`
- `HUNTER_API_KEY`
- `GOOGLE_CSE_API_KEY` + `GOOGLE_CSE_CX`
- `NVD_API_KEY`

### Secrets and `SECRET_KEY`

`SECRET_KEY` does two things:

1. Signs HS256 session JWTs.
2. Derives the Fernet key that encrypts stored per-account provider keys.

Generate a strong value for any non-local deployment:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Rotating `SECRET_KEY` invalidates all sessions and all stored provider keys by
design. The application refuses to boot in `ENVIRONMENT=production` with the
default development secret.

Never commit `.env`; it is ignored by `.gitignore`. Commit only
`.env.example`.

---

## Usage guide

### Create the first account

1. Open <http://localhost:5173/register>.
2. Enter an email, password (minimum 8 characters), and optional display name.
3. You are signed in automatically with a 7-day bearer token.

Set `ALLOW_REGISTRATION=false` and restart the API to disable further sign-ups.

### Run a scan

1. Enter a domain (`example.com`), IPv4 address, or IPv6 address.
2. Choose **Passive Intelligence** or **Web Surface Collection**.
3. Choose **Run Full Intelligence** (recommended modules) or **Configure
   modules** to select a custom set.
4. Watch real module-by-module progress. Every checkmark is a completed,
   skipped, or failed module — there are no simulated progress bars.
5. Results appear as soon as the scan reaches a terminal state
   (`completed`, `partial`, `failed`, or `cancelled`).

A scan ending in `partial` is normal when optional credentials are absent or a
provider is unreachable. The module list explains exactly which module was
skipped or failed and why.

### Explore results

Each scan exposes:

- **Overview** — exposure score, severity distribution, collection health.
- **Domains & Subdomains** — registrable domain, DNS delegation, discovered
  hostnames, DNS records.
- **IPs / ASN** — resolved addresses, ASN/netblock, network reputation.
- **Certificates** — CT certificates, SANs, issuers, validity, fingerprints.
- **Technologies** — frameworks, servers, libraries, version evidence and
  confidence.
- **JavaScript** — discovered bundles, endpoints, source maps, secret
  indicators (masked), third-party libraries.
- **URLs / APIs** — crawled URLs, parameters, REST/GraphQL/WebSocket/OpenAPI
  endpoints.
- **Identity** — publicly harvested emails, breach metadata (never passwords),
  social and corporate footprint.
- **Documents** — publicly linked documents and metadata.
- **Historical** — Wayback/Common Crawl/URLScan observations and snapshot diffs.
- **Indexed Exposure** — artifacts visible in public indexes.
- **Findings** — severity-ranked findings with evidence and recommendations.
- **Changes** — diff against another scan of the same target.
- **Asset Graph** — interactive relationship graph (d3-force).
- **Reports** — PDF, Markdown, JSON.

### Download reports

Use the **PDF / Markdown / JSON** buttons on a scan, or fetch directly:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -o insyte-report.pdf \
  http://localhost:8000/api/scans/$SCAN_ID/report/pdf
```

Reports are available only for `completed` or `partial` scans.

### Scheduled scans

```bash
curl -X POST http://localhost:8000/api/schedules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","mode":"passive","modules":[],"interval_hours":24}'
```

- `modules: []` means the recommended set.
- `interval_hours` accepts 1–720.
- The first firing happens on the next Celery Beat tick (within minutes), then
  repeats every `interval_hours`.
- `PATCH /api/schedules/{id}` with `{"enabled": false}` pauses a schedule.
- `DELETE /api/schedules/{id}` removes it.
- Run exactly **one** `beat` replica. Two beats would double-fire schedules.

### Per-account provider credentials

```bash
curl -X PUT http://localhost:8000/api/credentials/shodan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"api_key":"YOUR_KEY"}}'
```

- Values are encrypted at rest and never returned; reads expose only a hint.
- Sending an empty string clears a stored field.
- User keys override environment defaults for that user's scans.
- Removing or rotating `SECRET_KEY` makes previously stored ciphertext
  undecryptable by design; re-enter the keys.

---

## Local development

### Backend

Requirements: Python 3.13, PostgreSQL 16, Redis 7.

```bash
cd backend
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export DATABASE_URL="postgresql+psycopg://insyte:insyte@localhost:5432/insyte"
export REDIS_URL="redis://localhost:6379/0"
export CELERY_BROKER_URL="redis://localhost:6379/1"
export CELERY_RESULT_BACKEND="redis://localhost:6379/2"

alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

In a second terminal, start a worker:

```bash
cd backend
source .venv/bin/activate
celery -A app.workers.celery_app.celery worker -l info --concurrency=2
```

If you prefer Docker only for infrastructure, add a local override that
publishes PostgreSQL and Redis:

```yaml
# docker-compose.override.yml
services:
  postgres:
    ports: ["5432:5432"]
  redis:
    ports: ["6379:6379"]
```

Then `docker compose up -d postgres redis`.

### Frontend

Requirements: Node.js 22+.

```bash
cd frontend
npm ci
VITE_API_URL=http://localhost:8000 npm run dev
```

The dev server listens on <http://localhost:5173>.

### Run everything without building images

```bash
# terminal 1
docker compose up -d postgres redis
# terminal 2
cd backend && uvicorn app.main:app --reload
# terminal 3
cd backend && celery -A app.workers.celery_app.celery worker -l info
# terminal 4
cd frontend && npm run dev
```

---

## API reference

Base URL: `http://localhost:8000`. All routes except `/health` live under
`/api`. Protected routes require `Authorization: Bearer <token>`.

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create an account, returns a token |
| `POST` | `/api/auth/login` | Authenticate, returns a token |
| `GET` | `/api/auth/me` | Current account |

### Scans

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scans` | Create a scan (`target`, `mode`, `modules`, optional `project_id`) |
| `GET` | `/api/scans` | List your scans (`limit`, `offset`, `status`, `target`) |
| `GET` | `/api/scans/{id}` | Scan detail and module statuses |
| `DELETE` | `/api/scans/{id}` | Delete a scan |
| `POST` | `/api/scans/{id}/cancel` | Cancel a queued/running scan |
| `GET` | `/api/scans/{id}/progress` | Poll status, progress, module states |
| `GET` | `/api/scans/{id}/logs` | Structured scan logs (`since_sequence`) |

### Results

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/scans/{id}/assets` | Asset explorer (paged) |
| `GET` | `/api/scans/{id}/assets/{asset_id}` | Asset detail |
| `GET` | `/api/scans/{id}/graph` | Asset graph nodes/edges |
| `GET` | `/api/scans/{id}/findings` | Findings |
| `GET` | `/api/scans/{id}/findings/{finding_id}` | Finding detail |
| `GET` | `/api/scans/{id}/exposure` | Exposure score breakdown |
| `GET` | `/api/scans/{id}/technologies` | Detected technologies |
| `GET` | `/api/scans/{id}/cves` | Correlated CVEs |
| `GET` | `/api/scans/{id}/urls` | Collected URLs |
| `GET` | `/api/scans/{id}/apis` | Discovered APIs |
| `GET` | `/api/scans/{id}/javascript` | JavaScript artifacts |
| `GET` | `/api/scans/{id}/historical` | Historical observations |
| `GET` | `/api/scans/{id}/indexed-exposures` | Indexed exposures |
| `GET` | `/api/scans/{id}/certificates` | Certificates |
| `GET` | `/api/scans/{id}/dns-records` | DNS records |
| `GET` | `/api/scans/{id}/changes` | Diff against another scan |

### Reports

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/scans/{id}/report/pdf` | PDF report |
| `GET` | `/api/scans/{id}/report/md` | Markdown report |
| `GET` | `/api/scans/{id}/report/json` | JSON report |

### Catalogue and settings

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/modules` | Module catalogue (29) |
| `GET` | `/api/providers` | Provider catalogue (32) |
| `GET` | `/api/security-policy` | Effective collection/security policy |
| `GET` | `/api/settings` | Effective limits and provider status |

### Projects

| Method | Path | Description |
|---|---|---|
| `GET` / `POST` | `/api/projects` | List / create projects |
| `GET` / `PUT` / `DELETE` | `/api/projects/{id}` | Read / update / delete |
| `GET` | `/api/projects/{id}/scans` | Scans in a project |

### Schedules

| Method | Path | Description |
|---|---|---|
| `POST` / `GET` | `/api/schedules` | Create / list schedules |
| `GET` / `PATCH` / `DELETE` | `/api/schedules/{id}` | Read / enable-disable / delete |

### Credentials

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/credentials` | Per-provider configuration status |
| `PUT` | `/api/credentials/{provider_id}` | Set fields (empty string clears) |
| `DELETE` | `/api/credentials/{provider_id}` | Remove stored fields |

### Example: register, scan, poll, report

```bash
BASE=http://localhost:8000

TOKEN=$(curl -s -X POST "$BASE/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"change-me-123"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

SCAN_ID=$(curl -s -X POST "$BASE/api/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","mode":"passive","modules":[]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl -s "$BASE/api/scans/$SCAN_ID/progress" \
  -H "Authorization: Bearer $TOKEN"

curl -s -H "Authorization: Bearer $TOKEN" \
  -o report.pdf "$BASE/api/scans/$SCAN_ID/report/pdf"
```

Full interactive documentation: <http://localhost:8000/docs>.

---

## Data model

PostgreSQL, 25 tables. JSONB is used for structured evidence, provider
responses, and module summaries; UUIDs are native.

| Group | Tables |
|---|---|
| Accounts | `users`, `api_credentials` |
| Scans | `scans`, `scan_modules`, `scan_logs`, `scan_tags`, `scan_schedules`, `reports` |
| Assets | `targets`, `assets`, `asset_relationships`, `observations`, `projects` |
| Intelligence | `dns_records`, `certificates`, `technologies`, `urls`, `api_endpoints`, `javascript_artifacts`, `artifacts`, `historical_events`, `indexed_exposures`, `sources` |
| Risk | `findings`, `cves` |

Every asset observation records the source that reported it and how it relates
to *now* (`observed`, `historical`, `removed_from_source`, `unknown`). A source
ceasing to report an asset is never presented as proof that the asset was
removed.

---

## Security model

Insyte is built to process untrusted, attacker-influenced content safely.

- **SSRF protection on every outbound request.** Destination IPs are resolved
  and validated against private/reserved ranges *before* connecting; the
  connection is pinned to the validated address (closing the DNS-rebinding
  window); every redirect hop is re-validated from scratch. The test suite
  covers real-world bypass techniques including decimal/octal/hex IP encodings,
  IPv4-mapped and Teredo-embedded IPv6, cloud metadata endpoints, internal
  service names, and NAT64 well-known prefixes.
- **GET/HEAD only, byte-capped.** Modules receive a shared guarded HTTP client;
  they cannot construct their own client or send a mutating request. Response
  sizes and redirect counts are capped per content type.
- **Secrets masked at the source.** Secret-shaped JavaScript values are stored
  only as a masked preview plus a SHA-256 digest.
- **Parameterized SQL only.** SQLAlchemy ORM/Core throughout; no string-built
  queries.
- **No mass assignment.** Scan engine-owned state (status, progress, exposure
  score) has no writable API schema.
- **Generic errors.** Unhandled exceptions return a correlation ID and a generic
  message; details stay in server-side logs.
- **Path traversal closed by construction.** Report and artifact filenames are
  derived from UUIDs and sanitized slugs, never from raw target input.
- **Authentication.** scrypt password hashing with constant-time verification
  and a decoy hash for missing accounts (timing-safe-ish login); HS256 JWTs;
  owner-scoped queries return `404` for other users' resources.
- **Credential encryption.** Per-account provider keys are encrypted with
  Fernet; the encryption key is derived from `SECRET_KEY`.
- **CORS.** Exact origins only, credentials disabled; bearer tokens travel in
  the `Authorization` header.
- **Non-root containers.** The API/worker run as an unprivileged user; the
  frontend runtime also drops to a non-root user.
- **Security headers.** A middleware sets defensive headers on responses; HSTS
  is opt-in because it is unsafe over plain HTTP.

The historical audit of the predecessor codebase — including every issue found
and how it was closed — is in [`docs/AUDIT.md`](docs/AUDIT.md).

### Ethical use

Insyte's product boundary is **intelligence collection and correlation, not
exploitation**. It never exploits, brute-forces, fuzzes, authenticates, or
validates discovered credentials. Web Surface Collection never sends anything
beyond a read-only GET to an already-linked, already-known URL. Use it only
against targets you are authorized to assess. You are responsible for complying
with the laws and terms that apply to your targets.

---

## Testing and quality

### Backend

180 tests covering SSRF policy, target validation, secret masking, URL
canonicalization, confidence/risk scoring, persistence safety, API contracts,
authentication, credentials, and schedules.

```bash
cd backend
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

Or run the suite in a throwaway container:

```bash
docker run --rm --user root -v "$PWD/backend:/app" -w /app python:3.13-slim \
  bash -c "pip install -q -r requirements-dev.txt && pytest -q"
```

Static analysis:

```bash
cd backend
ruff check app/
bandit -r app/ -c pyproject.toml
mypy app/
pip-audit
```

### Frontend

```bash
cd frontend
npm ci
npm run build
npm run typecheck
npm run lint
```

CI (`.github/workflows/ci.yml`) runs backend tests, frontend typecheck/build,
and Docker image builds on every push and pull request.

---

## Operations

### Logs

```bash
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f beat
```

### Rebuild after code changes

```bash
git pull
docker compose up -d --build
```

Migrations run automatically via `backend/entrypoint.sh`.

### Scale scan workers

```bash
docker compose up -d --scale worker=3
```

The worker service has no fixed `container_name`, so Compose can create
replicas. `task_acks_late` + `task_reject_on_worker_lost` redeliver a scan if a
worker dies, and the Redis visibility timeout (1 hour) exceeds the scan hard
limit (30 minutes), so a long scan is not executed twice.

**Do not scale `beat`.** Exactly one scheduler replica is required.

### Database backup / restore

```bash
# backup
docker compose exec -T postgres pg_dump -U insyte insyte > insyte-backup.sql

# restore
cat insyte-backup.sql | docker compose exec -T postgres psql -U insyte -d insyte
```

Report files live on the `insyte_reports` Docker volume. Back it up separately if
you need to retain generated PDFs/Markdown/JSON.

### Reverse proxy / HTTPS

Put Insyte behind a TLS-terminating reverse proxy (Caddy, nginx, Traefik) and:

1. Set `INSYTE_PUBLIC_API_URL=https://insyte.example.com` and rebuild the
   frontend (Vite inlines this value).
2. Add the public origin to `CORS_ORIGINS`.
3. Set `ENABLE_HSTS=true` only after HTTPS is verified.
4. Set a strong `SECRET_KEY` and `ENVIRONMENT=production`.
5. Consider `ALLOW_REGISTRATION=false` for private deployments.

### Upgrading

Database migrations are additive and run on API/worker startup. Take a backup
before upgrading across major versions.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Cannot connect to the Docker daemon` | Start Docker (`sudo systemctl start docker`) and verify with `docker info`. |
| Port `5173` or `8000` already in use | Stop the conflicting service or change the published port in `docker-compose.yml`. |
| Health says `worker_alive: false` right after startup | Worker liveness is cached for ~30 seconds. Wait and re-check; if it persists, inspect `docker compose logs worker`. |
| Worker is up but scans stay `queued` | Check Redis connectivity and that the worker command is running. If no worker ever picks up a scan, reads reap it after `SCAN_PICKUP_TIMEOUT`. |
| Scan ends `partial` | Normal when optional keys are missing or a provider is unreachable. Open the scan and read the module status list for the exact reason. |
| `SSRFBlocked: ... NAT64 well-known prefix` | The host resolves public names to `64:ff9b::/96` (NAT64). The SSRF guard refuses that range by design. Use a network with native IPv4/IPv6 resolution, or run the containers with IPv4 DNS. |
| `401 Unauthorized` after restart | `SECRET_KEY` changed, invalidating tokens. Sign in again. |
| Browser console shows CORS errors | Add the exact browser origin (scheme + host + port) to `CORS_ORIGINS`, then restart the API. |
| Frontend cannot reach the API | `INSYTE_PUBLIC_API_URL` is baked at build time. Change it in `.env` and run `docker compose up -d --build frontend`. |
| Report download 404 after restart | Report files live on the `insyte_reports` volume. If the volume was removed, regenerate the report from the scan. |
| `permission denied` on cache files after running tests as root | Tests run in containers as root. Remove caches with `docker run --rm -v "$PWD:/src" alpine find /src -name __pycache__ -prune -exec rm -rf {} +`. |
| Registration disabled | `ALLOW_REGISTRATION=false`. Set it back to `true` and restart, or create users directly in the database. |

---

## Project structure

```text
insyte/
├── backend/
│   ├── app/
│   │   ├── api/            REST routes and dependencies
│   │   ├── core/           config, crypto, target parsing, SSRF HTTP client
│   │   ├── database/       SQLAlchemy engine, session, base
│   │   ├── models/         ORM models (25 tables)
│   │   ├── modules/        29 intelligence modules
│   │   ├── providers/      32 external provider adapters
│   │   ├── schemas/        Pydantic request/response schemas
│   │   ├── services/       correlation, risk, CVE, reports, scan orchestration
│   │   └── workers/        Celery app, tasks, liveness
│   ├── alembic/            database migrations
│   ├── tests/              unit / integration / security
│   ├── Dockerfile
│   └── requirements*.txt
├── frontend/
│   ├── src/
│   │   ├── routes/         TanStack Router file routes
│   │   ├── components/     shadcn/ui primitives + app components
│   │   ├── api/            typed API client
│   │   └── lib/            auth, theme, formatting, scan context
│   ├── Dockerfile
│   └── server.mjs          Node adapter for the SSR build
├── docs/
│   ├── AUDIT.md            predecessor-repository audit
│   ├── openapi.json        exported API schema
│   └── screenshots/        README images
├── .github/workflows/      CI
├── docker-compose.yml
├── .env.example
├── Makefile
├── README.md
└── LICENSE
```

---

## Known limitations

- **NVD rate limits.** Without `NVD_API_KEY`, NVD allows 5 requests per 30
  seconds. Large scans may check only the 25 highest-confidence technologies;
  the truncation is logged and shown in the report appendix.
- **Version-range CVE mapping depends on curated CPE knowledge.** Unmapped
  technologies fall back to a capped keyword search and are reported as
  non-definitive leads, never findings.
- **Archive coverage varies.** Historical intelligence quality depends on
  Wayback, Common Crawl, and URLScan coverage for the target.
- **Free providers rate-limit.** Insyte respects provider budgets; a heavily
  rate-limited provider returns fewer results rather than failing the scan.
- **TLD extraction uses a curated allowlist** to avoid false positives on
  minified JavaScript identifiers. Rare ccTLDs may be missed.
- **Single-region deployment by default.** The API and workers are stateless
  apart from PostgreSQL/Redis and the reports volume; horizontal scaling is
  supported, but no Kubernetes manifests are included.
- **No built-in TLS.** Use a reverse proxy for HTTPS.
- **No password reset email flow.** Accounts are created locally; there is no
  external mail integration for recovery.

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository and create a feature branch.
2. Keep the backend test suite green (`pytest -q`) and frontend typecheck clean.
3. Add tests for new modules, providers, or API behavior.
4. Do not add exploit, brute-force, fuzzing, or authentication functionality —
   those are outside the product boundary.
5. Open a pull request describing the change and its security impact.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full workflow.

For security vulnerabilities in Insyte itself, follow [`SECURITY.md`](SECURITY.md);
please do not open a public issue.

---

## License

Released under the [MIT License](LICENSE).

Copyright © 2026 Insyte contributors.

---

<div align="center">

**Insyte — Passive Exposure Intelligence**

*Collect evidence. Correlate it honestly. Never pretend to know more than the data does.*

</div>
