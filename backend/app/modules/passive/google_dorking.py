"""Google Dorking - GHDB-style search-engine reconnaissance.

Every query below is a read against Google's own index via the
Programmable Search JSON API (`providers.osint.GoogleCseProvider`) - never
a request to the scan target. A hit here means "Google has this indexed",
which is `ExposureLevel.INDEXED` by definition: Insyte does not then fetch
the URL to confirm it is still live, the same restraint `indexed_exposure`
applies to archive-sourced URLs.

The category labels are drawn from the public Google Hacking Database
(exploit-db.com/google-hacking-database) taxonomy where a template matches
a documented GHDB category, and are inline commentary where it does not
(the tech-stack-leakage-via-job-postings template deliberately does not
scope to `site:{domain}` at all - it searches job boards for the target's
name alongside infrastructure keywords, which is a legitimate GHDB-style
technique but not a `site:` dork).

Entirely useless without a configured CSE key/CX pair, so
`requires_api_key = True` makes the module skip itself with a clear reason
rather than run and find nothing - the same pattern `github_intelligence`
uses for its own single-provider dependency.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from app.core.contracts import ExposureRecord, FindingRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import (
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext
from app.providers import get_provider

#: (GHDB-style category label, query template, severity if a hit is found,
#: exposure_type slug). `{domain}` is substituted with the target's
#: registrable domain.
_DORK_TEMPLATES: tuple[tuple[str, str, Severity, str], ...] = (
    (
        "Files Containing Passwords",
        'site:{domain} ext:env OR ext:yml OR ext:yaml OR ext:ini "DB_PASSWORD" OR "SECRET_KEY"',
        Severity.HIGH,
        "credential_config_file",
    ),
    (
        "Sensitive Directories",
        'site:{domain} intitle:"index of /"',
        Severity.MEDIUM,
        "directory_listing",
    ),
    (
        "Pages Containing Login Portals",
        "site:{domain} inurl:admin OR inurl:login OR inurl:wp-admin",
        Severity.LOW,
        "login_portal",
    ),
    (
        "Files Containing Passwords",
        "site:{domain} ext:sql OR ext:db OR ext:sqlite",
        Severity.HIGH,
        "database_file",
    ),
    (
        "Vulnerable Files",
        "site:{domain} ext:bak OR ext:backup OR ext:old",
        Severity.MEDIUM,
        "backup_file",
    ),
    (
        "Advisories and Vulnerabilities",
        "site:{domain} inurl:swagger OR inurl:openapi OR inurl:api-docs",
        Severity.MEDIUM,
        "api_documentation",
    ),
    (
        "Files Containing Juicy Info",
        "site:{domain} ext:log",
        Severity.MEDIUM,
        "log_file",
    ),
    (
        "Files Containing Juicy Info",
        'site:{domain} ext:pdf OR ext:doc OR ext:xls "confidential" OR "internal"',
        Severity.MEDIUM,
        "confidential_document",
    ),
    (
        "Sensitive Directories",
        'site:{domain} inurl:".git"',
        Severity.HIGH,
        "version_control_exposure",
    ),
    (
        "Error Messages",
        'site:{domain} "fatal error" OR "warning: mysql" OR "unhandled exception"',
        Severity.LOW,
        "error_message",
    ),
    (
        "Network or Vulnerability Data",
        "site:{domain} inurl:s3.amazonaws.com OR inurl:blob.core.windows.net",
        Severity.MEDIUM,
        "cloud_storage_reference",
    ),
    (
        "Tech Stack Leakage",
        'site:linkedin.com/jobs OR site:indeed.com "{domain}" "VPN" OR "AWS" OR "on-call"',
        Severity.INFORMATIONAL,
        "job_posting_tech_leakage",
    ),
    (
        "Files Containing Usernames",
        'site:{domain} filetype:csv "username" OR "email"',
        Severity.MEDIUM,
        "user_data_export",
    ),
    (
        "Vulnerable Files",
        'site:{domain} ext:php intitle:phpinfo "PHP Version"',
        Severity.MEDIUM,
        "phpinfo_exposure",
    ),
    (
        "Sensitive Directories",
        'site:{domain} inurl:wp-content OR inurl:uploads intitle:"index of"',
        Severity.LOW,
        "upload_directory_listing",
    ),
    (
        "Footholds",
        "site:{domain} inurl:cgi-bin",
        Severity.LOW,
        "cgi_bin_exposure",
    ),
    (
        "Files Containing Passwords",
        'site:{domain} "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"',
        Severity.HIGH,
        "private_key_exposure",
    ),
    (
        "Sensitive Online Shopping Info",
        'site:{domain} ext:xls OR ext:csv "invoice" OR "order" "customer"',
        Severity.MEDIUM,
        "customer_data_export",
    ),
    (
        "Advisories and Vulnerabilities",
        '"{domain}" site:exploit-db.com',
        Severity.MEDIUM,
        "public_exploit_reference",
    ),
    (
        "Various Online Devices",
        "site:{domain} inurl:viewerframe OR inurl:videostream.cgi",
        Severity.MEDIUM,
        "exposed_device_interface",
    ),
    (
        "Pages Containing Login Portals",
        'site:{domain} intitle:"Jenkins" OR intitle:"GitLab Sign in"',
        Severity.MEDIUM,
        "devops_tool_portal",
    ),
    (
        "Vulnerable Files",
        'site:{domain} ext:yml "version:" "image:"',
        Severity.LOW,
        "ci_cd_config_exposure",
    ),
    (
        "Sensitive Directories",
        "site:{domain} inurl:phpmyadmin",
        Severity.MEDIUM,
        "database_admin_portal",
    ),
    (
        "Files Containing Juicy Info",
        'site:{domain} ext:xml "password" OR "connectionstring"',
        Severity.HIGH,
        "credential_bearing_xml",
    ),
    (
        "Web Server Detection",
        'site:{domain} intitle:"welcome to nginx" OR intitle:"apache2 debian default page"',
        Severity.LOW,
        "default_server_page",
    ),
    (
        "Files Containing Juicy Info",
        'site:{domain} ext:json "api_key" OR "client_secret"',
        Severity.HIGH,
        "credential_bearing_json",
    ),
    (
        "Sensitive Directories",
        'site:{domain} inurl:".svn" OR inurl:".hg"',
        Severity.MEDIUM,
        "version_control_exposure",
    ),
    (
        "Tech Stack Leakage",
        'site:stackoverflow.com "{domain}" "error" OR "exception"',
        Severity.INFORMATIONAL,
        "stackoverflow_tech_leakage",
    ),
)

#: Google's free CSE tier is 100 queries/day. Running the full catalogue
#: (~28 templates) on every scan of every target would burn through that
#: fast for anyone running more than a couple of scans a day, so a single
#: scan runs at most this many - well under half the daily budget even
#: allowing for a re-scan or two.
MAX_DORKS_PER_SCAN = 20


class GoogleDorkingModule(IntelligenceModule):
    id = "google_dorking"
    name = "Google Dorking"
    description = (
        "Runs a curated set of GHDB-style Google dork queries against the "
        "target domain via the Google Programmable Search API - read-only "
        "queries against Google's own index, never a request to the "
        "target itself."
    )
    category = ModuleCategory.EXPOSURE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    providers = ("google_cse",)
    requires_api_key = True
    timeout = 90.0
    order = 86

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        provider = get_provider("google_cse")
        if provider is None:
            output.skip_reason = "google_cse provider is not registered"
            return output

        domain = ctx.target.registrable or ctx.target.value
        templates = _DORK_TEMPLATES[:MAX_DORKS_PER_SCAN]
        skipped = len(_DORK_TEMPLATES) - len(templates)

        dorks_run = 0
        total_hits = 0
        for category_label, template, severity, exposure_type in templates:
            ctx.check_cancelled()
            query = template.format(domain=domain)
            results = provider.search(query, num=10)
            dorks_run += 1
            total_hits += len(results)

            for result in results:
                host = urlsplit(result["url"]).hostname
                output.exposures.append(
                    ExposureRecord(
                        exposure_type=exposure_type,
                        url=result["url"],
                        observation_class="indexed",
                        host=host,
                        severity=severity,
                        confidence=60,
                        retrievable=False,
                        sources=["google_cse"],
                        evidence={
                            "dork_category": category_label,
                            "query": query,
                            "title": result["title"],
                            "snippet": result["snippet"],
                        },
                    )
                )
                # Generic indexed pages (a login portal existing, a
                # nginx welcome page) are not worth a finding on their
                # own - only the categories severe enough to warrant an
                # analyst's attention generate one.
                if severity.rank >= Severity.MEDIUM.rank:
                    output.findings.append(
                        FindingRecord(
                            module_id=self.id,
                            category=FindingCategory.INDEXED_ARTIFACT,
                            severity=severity,
                            title=(
                                f"Google-indexed {exposure_type.replace('_', ' ')} "
                                f"({category_label})"
                            ),
                            description=(
                                f"{result['url']} is indexed by Google under a "
                                f'"{category_label}"-style dork: {query}'
                            ),
                            recommendation=(
                                "Confirm whether this resource should be publicly "
                                "indexed; remove, restrict, or noindex it if not."
                            ),
                            location=result["url"],
                            confidence=60,
                            exposure=ExposureLevel.INDEXED,
                            sources=["google_cse"],
                            evidence={
                                "dork_category": category_label,
                                "query": query,
                                "snippet": result["snippet"],
                            },
                        )
                    )

        output.providers.append(provider.status_snapshot(result_count=total_hits))
        output.data["summary"] = {
            "dorks_run": dorks_run,
            "dorks_skipped_over_budget": skipped,
            "total_hits": total_hits,
        }
        return output
