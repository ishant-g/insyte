# Security Policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

| Version | Supported |
|---|---|
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report it privately through GitHub's
[Security Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
for this repository ("Security" tab → "Report a vulnerability").

Please include:

- A clear description of the issue and its impact.
- The affected component (API, worker, frontend, container, report engine).
- Reproduction steps or a minimal proof of concept.
- The version/commit you tested.
- Any suggested remediation.

You can expect an acknowledgement within 72 hours and a status update within
7 days. Please give us reasonable time to fix the issue before public
disclosure.

## Scope

In scope:

- Insyte's own code in this repository.
- Authentication and authorization logic.
- SSRF protections and outbound request handling.
- Secret masking and credential encryption.
- Report generation and file handling.
- Container configuration shipped in `docker-compose.yml` and the Dockerfiles.

Out of scope:

- Vulnerabilities in third-party services queried by Insyte.
- Issues that require a compromised host, database, or Redis instance.
- Findings that depend on `ALLOW_PRIVATE_TARGETS=true` or other explicitly
  unsafe development settings.
- Missing hardening headers without a demonstrated impact.
- Rate limiting on non-authentication endpoints.
- Social engineering or physical attacks.

## Safe harbor

We will not pursue legal action against researchers who:

- Test only against their own deployment or an explicitly authorized target.
- Avoid privacy violations, data destruction, and service disruption.
- Report findings privately and give us time to remediate.
- Do not use a finding to access data that does not belong to them.

## Deployment hardening checklist

- [ ] Set a strong random `SECRET_KEY`.
- [ ] Set `ENVIRONMENT=production`.
- [ ] Set `ALLOW_REGISTRATION=false` if accounts are managed internally.
- [ ] Serve over HTTPS via a reverse proxy and set `ENABLE_HSTS=true`.
- [ ] Restrict database and Redis to the private network.
- [ ] Back up PostgreSQL and the `insyte_reports` volume.
- [ ] Keep provider API keys in `.env` or per-account credentials; never commit
      them.
- [ ] Review `CORS_ORIGINS` and use exact origins.
- [ ] Run exactly one `beat` replica.
