# Insyte — Source Repository Audit

Audit of the predecessor repository (`reconcomp/Recon Compass-updated/Recon Compass-updated`)
performed before any code was written, per the rebuild brief's rule 0
("Do NOT blindly rewrite the repository").

- Source tree size: 338 tracked-relevant files (excluding `.venv`, `venv`, `node_modules`, `__pycache__`)
- Backend: ~21,800 lines of Python across 168 modules
- Frontend: ~6,000 lines of TS/TSX (excluding 46 shadcn/ui primitives)

---

## 1. Dependency map

### Backend (`backend/requirements.txt`)

| Package | Pinned | Status |
|---|---|---|
| fastapi | 0.115.0 | Keep, bump |
| uvicorn[standard] | 0.30.6 | Keep, bump |
| sqlalchemy | 2.0.35 | Keep — already SQLAlchemy 2.x style (`Mapped`, `mapped_column`) |
| alembic | 1.13.3 | Keep |
| **pymysql** | 1.1.1 | **REMOVE** — MySQL driver, contradicts the PostgreSQL target |
| pydantic / pydantic-settings | 2.9.2 / 2.5.2 | Keep |
| redis | 5.0.8 | Keep |
| celery | 5.4.0 | Keep — **but no Celery task is defined anywhere** |
| httpx | 0.27.2 | Keep — the only HTTP client; used unguarded (see security map) |
| dnspython | 2.6.1 | Keep |
| python-whois | 0.9.5 | Replace/augment — shells out to `whois`, unreliable in containers; RDAP over HTTP is better |
| cryptography | 43.0.1 | Keep — used for certificate parsing |
| python-json-logger | 2.0.7 | Keep |
| **reportlab** | *missing* | **BROKEN** — `app/report_generator/*` imports `reportlab` but it is not in requirements. PDF generation cannot work from a clean install. |
| **psycopg** | *missing* | **BROKEN** — no PostgreSQL driver despite `docker-compose.yml` provisioning PostgreSQL 16 |

Undeclared-but-imported: `reportlab`. Declared-but-wrong: `pymysql`.

### Frontend (`package.json`)

- Name is the untouched template name `tanstack_start_ts`.
- Stack: React 19.2, TanStack Start 1.168 + Router 1.170, TanStack Query 5.101,
  Tailwind CSS 4.2 (Vite plugin), Radix UI primitives, `lucide-react`, `recharts`,
  `sonner`, `zod`. All current and worth keeping.
- **`@lovable.dev/vite-tanstack-config` (devDependency)** — third-party build config
  from the old Lovable scaffold. Must go.
- Two lockfiles present (`bun.lock` *and* `package-lock.json`) — ambiguous package
  manager. `bun` is not installed on the build host; npm is. Standardise on npm.
- No test tooling at all: no vitest, no testing-library, no playwright.

---

## 2. Module map (reusable reconnaissance logic)

The single strongest asset in the old repository. 13 registered modules under
`backend/app/scan_engine/modules/`, each with a consistent internal shape
(`module.py` + `helpers.py` + `parser.py` + `constants.py` + `findings.py`,
plus `detectors/`, `extractors/` or `sources/` sub-packages).

| Module | Order | LOC (approx) | Verdict |
|---|---|---|---|
| `domain_information` | 10 | 560 | **Reuse** — resolution + HTTP probe + CDN hints |
| `dns_records` | 20 | 495 | **Reuse & expand** — A/AAAA/MX/NS/TXT only; needs SOA/CAA/SRV/NAPTR/DS/DNSKEY/TLSA/PTR |
| `whois_information` | 30 | 430 | **Reuse parser, replace transport** — good tolerant parser, bad `python-whois` transport; add RDAP |
| `ssl_information` | 40 | 700 | **Reuse & expand** — needs CT correlation + SAN-to-domain graph edges |
| `security_headers` | 50 | 640 | **Reuse & expand** — missing COOP/CORP/COEP/Permissions-Policy |
| `technology_detection` | 60 | 1,050 | **Reuse** — 6 detectors (headers/html/meta/cookies/js/cdn), solid evidence model |
| `javascript_analysis` | 70 | 1,300 | **Reuse & promote to flagship** — already has endpoint/library/secret/comment/import extractors |
| `url_collection` | 80 | 1,700 | **Reuse** — HTML/JS/CSS/robots/sitemap extractors + a real URL normalizer |
| `api_discovery` | 90 | 1,400 | **Reuse** — REST/GraphQL/WebSocket/Swagger/auth/versioning detectors |
| `subdomains` | 100 | 1,000 | **Reuse & expand** — 5 sources (crt.sh, AlienVault, BufferOver, HackerTarget, RapidDNS); needs URLScan/Wayback/CommonCrawl/VT/Censys/Shodan/SecurityTrails/GitHub |
| `cloud_detection` | 110 | 1,400 | **Reuse** — 8 provider detectors on a shared base |
| `waf_detection` | 120 | 1,050 | **Reuse** — 5 signal detectors (headers/cookies/dns/ssl/technology) |
| `additional_checks` | 130 | 1,200 | **Split** — robots/sitemap/security.txt/humans.txt/favicon/email-security bundled into one module; email security and well-known deserve their own modules |

### Missing entirely (must be built)

IP/ASN intelligence · certificate-transparency-driven discovery as a first-class
module · source-map intelligence · document intelligence · indexed-exposure
intelligence · historical intelligence (Wayback / Common Crawl / URLScan) ·
GitHub intelligence · CVE/CVSS/EPSS/KEV correlation · asset graph ·
scan-to-scan diff · the whole external-provider adapter layer.

### Architecture verdict on the module layer

`module_base.py` / `module_config.py` / `registry.py` / `module_manager.py` is a
**good** design and is preserved conceptually:

- Registry holds data-only `ModuleConfig` with a lazy `factory` — disabled modules
  are never imported.
- `ModuleManager.execute()` is a generator yielding `(module, result, duration)`
  and swallows per-module exceptions, so one module cannot kill a scan. This is
  exactly the failure-isolation the brief asks for and it already works.
- `ModuleResult` v1.0.0 contract (`success/module/data/findings/technologies/metadata/errors`)
  is sound but **has no place for normalized observations, provenance, confidence,
  asset/relationship emission, or mode gating** — this is the main extension point.

Gaps to close in the module contract: `mode_support`, `input_types`,
`dependencies`, `requires_api_key`, `rate_limit`, `validate()`, `normalize()`,
and observation emission.

---

## 3. API map

Mounted with no version prefix — `api_router` has no `prefix`, so routes sit at
the bare root (`/health`, `/scans/{id}`, `/reports/{id}`) rather than under `/api`.

| Method | Path | Handler | Verdict |
|---|---|---|---|
| GET | `/health` | `routes/health.py` | Keep |
| GET | `/projects` | `routes/projects.py` | Keep (demote — project-centric flow is secondary) |
| GET | `/projects/{project_id}` | | Keep |
| POST | `/projects` | | Keep |
| PUT | `/projects/{project_id}` | | Keep |
| DELETE | `/projects/{project_id}` | | Keep |
| GET | `/projects/{project_id}/scans` | `routes/scans.py` | Keep |
| POST | `/projects/{project_id}/scans` | | **Replace** — a scan must be creatable from a bare target with no project |
| GET | `/scans/{scan_id}` | | Keep |
| PUT | `/scans/{scan_id}` | | **Remove** — client-writable scan status/progress is a mass-assignment hole |
| DELETE | `/scans/{scan_id}` | | Keep |
| POST | `/scans/{scan_id}/start` | | **Replace** — uses `BackgroundTasks`, not Celery |
| GET | `/scans/{scan_id}/logs` | `routes/logs.py` (394 LOC) | **Rewrite** — reads and parses the API process's own log file off disk |
| GET | `/reports/{scan_id}` | `routes/report.py` | **Replace** — PDF only; regenerates on every request; filename hardcodes old branding |

Absent: cancel, progress, per-module status, assets, relationships, findings,
technologies, urls, apis, javascript, historical, changes, markdown export,
JSON export. No pagination or filtering on any collection endpoint.

---

## 4. Frontend route / component map

TanStack Start file-based routing under `src/routes/`.

| Route | LOC | Data source | Verdict |
|---|---|---|---|
| `__root.tsx` | 126 | — | Rewrite — title "Passive Recon Platform", imports `reportLovableError` |
| `index.tsx` | 160 | **`@/lib/dummy-data`** | **Rewrite** — every number on the dashboard is fabricated |
| `projects.tsx` | 306 | real API | Rewrite for new IA |
| `projects.$projectId.tsx` | 233 | real API | Rewrite for new IA |
| `new-scan.tsx` | 298 | real API | **Rewrite** — forces project creation before a scan; no mode selector, no module selector |
| `scan-progress.tsx` | 393 | real API + log polling | Rewrite — progress is `index/total`, not real module state |
| `scan-results.tsx` | 462 | real API | Rewrite |
| `scans.$scanId.tsx` | **2,477** | real API | **Rewrite/split** — single monolithic file, contains three `<Placeholder>` panels for Findings/Reports that render nothing |
| `reports.tsx` | 51 | **`@/lib/dummy-data`** | **Rewrite** — fabricated report list with dead Download buttons |
| `settings.tsx` | 65 | none | Rewrite |

Components: `DashboardLayout.tsx` (114), `StatusBadge.tsx` (24), and 46 shadcn/ui
primitives under `src/components/ui/` — **the primitives are keepable**, the
application shell and every page are not.

`src/lib/`: `api-client.ts` (48, keep pattern), `api/scans.ts` (731, rewrite),
`api/projects.ts` (45), **`dummy-data.ts` (39, delete)**,
**`lovable-error-reporting.ts` (36, delete)**, `error-capture.ts`, `error-page.ts`.

Missing entirely: asset explorer, asset graph, API explorer, JavaScript explorer,
historical view, indexed-exposure view, evidence panel, CVE view, changes/diff view.

---

## 5. Database / schema map

`backend/alembic/versions/` — three revisions: `0001_initial`,
`5b6db19fb0a5_add_asset_inventory`, `76f0299c5489_add_risk_engine_fields_to_findings`.

| Table | Columns of note | Verdict |
|---|---|---|
| `projects` | id(String36), project_name, description, timestamps | Keep |
| `scans` | id, project_id **(NOT NULL)**, target_domain, scan_type, status, progress, timings, overall_risk, **13 `JSON` columns — one per module** | **Redesign** |
| `findings` | scan_id, module_name, severity, risk_score, priority, likelihood, confidence, title, description, recommendation, evidence(JSON), status | Keep and extend |
| `technologies` | scan_id, technology_name, version, category | **Extend** — no confidence, evidence, source, first/last seen |
| `assets` | scan_id, asset_type, asset_value, source_module, confidence, `metadata`(JSON) | Keep as the seed of the graph; needs relationships + observations |
| `reports` | scan_id (unique), report_name, pdf_path | Extend for md/json |

Critical defects:

1. **Dialect conflict.** `settings.DATABASE_URL` defaults to
   `mysql+pymysql://root:SunRaj%2F23@localhost:3306/passive_recon`
   while `docker-compose.yml` provisions `postgres:16-alpine` and the `Dockerfile`
   installs `default-libmysqlclient-dev`. Every model uses generic `JSON`, not
   `JSONB`. **A real password is hardcoded in the source default.**
2. **One JSON column per module.** Adding a module requires a migration, which
   defeats the stated purpose. Thirteen sparse JSON blobs also make correlation,
   dedup and cross-scan diff impossible to express in SQL.
3. **`scans.project_id` is NOT NULL**, so the brief's core workflow
   ("type a domain, press Run") is structurally impossible.
4. **`assets` maps a column to the name `metadata`** — a reserved attribute on
   SQLAlchemy's declarative base; it works only because it is aliased to the
   Python name `asset_metadata`, but it is fragile.
5. No table for: relationships, observations, sources, artifacts, dns_records,
   certificates, urls, api_endpoints, javascript_artifacts, cves, historical_events,
   scan_modules.
6. `String(36)` UUID text keys throughout instead of native `uuid`.

---

## 6. Report-generation map

Two byte-identical copies of the same package exist:
`app/report_generator/` (root-level, orphaned — outside `backend/`) and
`backend/app/report_generator/`. The root copy is dead code.

Structure: `builder.py` (205) → `models.py` (`ReportData`) → `generator.py`
(reportlab `SimpleDocTemplate`) → `sections.py` (298) → `constants.py` (theme)
→ `utils.py`.

- **Good:** clean separation of data assembly (`builder`) from rendering
  (`generator`/`sections`); reads real scan rows from the DB.
- **Bad:** PDF only. Branding string "Recon Compass" in `sections.py`,
  `generator.py`, `constants.py`. `reportlab` undeclared. Output written to a
  relative `generated_reports/` path resolved from the process CWD. Regenerated
  synchronously inside the request handler on every download. No pagination or
  chunking, so a large result set will overflow tables. Corporate-blue theme
  (`#1F4E79`) inherited from the old brand.
- `backend/generated_reports/` contains **7 committed PDF artifacts**.

---

## 7. Security-risk map

Ordered by severity. Every item is fixed in the rebuild.

### Critical

1. **No SSRF protection anywhere.** Modules construct `httpx.Client` inline
   (`additional_checks/helpers.py:65`, `subdomains/helpers.py:51,254`) and fetch
   attacker-influenced URLs — the scan target, URLs extracted from HTML/JS/CSS,
   `robots.txt` entries, sitemap entries, redirect targets. There is no
   destination-IP validation, no private/link-local/loopback blocking, no scheme
   allowlist, no redirect re-validation, and no DNS-rebinding defence. A target
   that returns `<script src="http://169.254.169.254/latest/meta-data/">` or
   redirects to `http://127.0.0.1:6379/` is followed. `subdomains/helpers.py`
   additionally calls `socket.gethostbyname` and probes arbitrary hostnames.
2. **Hardcoded database credential in source.** `app/config/settings.py`
   ships `mysql+pymysql://root:SunRaj%2F23@localhost:3306/passive_recon` as the
   `DATABASE_URL` default. `backend/.env` and `.env` are both present in the tree.
3. **`socket.setdefaulttimeout()` mutated process-wide** in
   `whois/helpers.py:41-46` and `subdomains/helpers.py:362-368`. Under Celery
   concurrency this races across tasks and silently changes unrelated sockets'
   timeouts.

### High

4. **CORS**: `allow_credentials=True` combined with `allow_methods=["*"]` and
   `allow_headers=["*"]` in `main.py`. Origins are configurable, but the
   credentialed-wildcard-methods shape is wrong for a no-auth app.
5. **No security headers** on Insyte's own responses — no CSP, no
   `X-Content-Type-Options`, no `Referrer-Policy`, no `Permissions-Policy`.
6. **`DEBUG: bool = True`** is the default in settings, and `FastAPI(debug=...)`
   is wired to it, so a default deployment serves tracebacks.
7. **Log-file-as-database.** `routes/logs.py` (394 LOC) opens, tails and parses
   the API process's own log file to serve scan logs over HTTP. Log lines are the
   only store of module progress; they leak internal paths, and in the Celery
   architecture the worker's logs are in a different container entirely.
   `backend/app/logs/app.log` is committed to the tree.
8. **Unbounded response reads.** No `max response size`, no per-artifact byte cap,
   no total-URL cap enforced at the transport layer. A hostile target can return a
   multi-gigabyte body and exhaust the worker.
9. **Secrets are not masked.** `javascript_analysis/extractors/secrets.py`
   extracts secret-like values into `Finding.evidence` (a JSON column) and they
   flow verbatim into API responses and the PDF.

### Medium

10. **`PUT /scans/{scan_id}`** lets any client set `status`, `progress`,
    `overall_risk`, `started_at`, `completed_at`, `duration` — mass assignment on
    engine-owned state.
11. **Report path built from a request-supplied id**
    (`report_service.py`: `output_dir / f"{scan_id}.pdf"`). It is constrained today
    only because FastAPI coerces the path param to `uuid.UUID`; the service
    function itself takes `scan_id: str` and does no validation, so any future
    non-UUID caller gets path traversal.
12. **XSS surface on the frontend.** Scan results are attacker-controlled
    (DNS TXT records, HTTP header values, certificate subjects, technology names,
    discovered filenames, API paths, page titles) and are rendered straight into
    JSX. React escapes text nodes, but URL-valued fields are placed into `href`
    with no scheme check, so a `javascript:` URL harvested from a target page is
    clickable. No sanitisation layer exists.
13. **`FastAPI` lifecycle uses deprecated `@app.on_event`** rather than a lifespan
    context manager.
14. **No rate limiting** against third-party providers (crt.sh, HackerTarget,
    RapidDNS, AlienVault, BufferOver) — the subdomain module fires all five
    concurrently with no backoff.

### Low / hygiene

15. `backend/venv/` (Windows `Scripts/*.exe`) and `.venv/` are both committed.
16. `$null` — a stray file created by a redirected PowerShell command, containing
    a `TASKKILL` usage error.
17. `.lovable/project.json`, `AGENTS.md` (Lovable notice), `bunfig.toml`
    (Lovable registry) and `vite.config.ts` (Lovable plugin) are old-scaffold
    residue.
18. `backend/generated_reports/*.pdf` (7 files), `backend/app/logs/app.log`,
    `__pycache__` trees.
19. `.gitignore` covers none of the above adequately.
20. No tests of any kind — no `tests/` directory, no CI, no lint config for the
    backend (no ruff/mypy/bandit configuration).

---

## 8. Preservation decisions

**Ported forward largely intact** (the brief's "do not delete working
reconnaissance logic merely because it was written in the old architecture"):

- The module framework concept: registry + lazy factory + generator-based manager
  with per-module exception isolation.
- All 13 reconnaissance modules' detection logic, constants tables, parsers,
  detectors and extractors.
- `result_processor`'s pipeline decomposition
  (validate → normalize → dedupe → process → store) — the stage boundaries are right.
- `risk_engine`'s rule-registry shape.
- `report_generator`'s builder/sections/generator split.
- The repository/service layering under `app/repositories` and `app/services`.
- shadcn/ui primitives and the `api-client` fetch-wrapper pattern on the frontend.

**Discarded:**

- MySQL/PyMySQL dialect and the hardcoded credential.
- 13-JSON-columns-on-`scans` schema.
- `BackgroundTasks` as the scan engine's execution substrate.
- `routes/logs.py`'s log-file parsing.
- `PUT /scans/{id}`.
- `src/lib/dummy-data.ts` and every component consuming it.
- Lovable scaffold residue and all old branding.
- The orphaned root-level `app/report_generator/` duplicate.
