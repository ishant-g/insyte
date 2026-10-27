"""Document Intelligence.

Catalogues document- and archive-type URLs already known to the scan -
PDFs, Office documents, spreadsheets, structured data files, and archives -
by extension alone. This is metadata cataloguing, not content inspection:
Insyte never downloads a document to read it, so nothing here can leak
whatever a PDF's metadata or an Excel file's cell contents might contain.

Archives get the one step further: an exposure record. A publicly
reachable `.zip` or `.tar.gz` is qualitatively more interesting than a
publicly reachable PDF brochure, because an archive is far likelier to
contain something that was never meant to be bundled for distribution.
"""

from __future__ import annotations

from app.core.canonical import canonical_url
from app.core.contracts import ExposureRecord, FindingRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: extension -> human document type. Deliberately broader than
#: `UrlClassification`, which splits yaml/json into CONFIGURATION and xml
#: into FEED - useful distinctions for URL routing, not for "what kind of
#: document is this" cataloguing.
_DOC_TYPE_MAP: dict[str, str] = {
    "pdf": "pdf",
    "doc": "word", "docx": "word",
    "xls": "excel", "xlsx": "excel",
    "csv": "csv", "tsv": "csv",
    "txt": "text",
    "xml": "xml",
    "json": "json",
    "yaml": "yaml", "yml": "yaml",
    "zip": "archive", "tar": "archive", "gz": "archive", "tgz": "archive",
    "bz2": "archive", "xz": "archive", "7z": "archive", "rar": "archive",
}


class DocumentIntelligenceModule(IntelligenceModule):
    id = "document_intelligence"
    name = "Document Intelligence"
    description = (
        "Catalogues document- and archive-type URLs already known to the "
        "scan by extension, and flags publicly reachable archives as an "
        "exposure. Metadata only - nothing is downloaded to inspect."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    # Declared so the historical-URL expansion below actually sees
    # historical output - without ordering it usually runs concurrently and
    # sees nothing.
    dependencies = ("historical_intelligence",)
    timeout = 20.0
    order = 80

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target_host = ctx.target.value

        seen: dict[str, dict] = {}

        url_output = ctx.output_of("url_collection")
        if url_output is not None:
            for record in url_output.urls:
                seen.setdefault(
                    record.normalized_url,
                    {
                        "url": record.url,
                        "host": record.host,
                        "path": record.path,
                        "extension": record.extension,
                        "status_code": record.status_code,
                        "source": "url_collection",
                        "first_seen": record.first_seen,
                        "last_seen": record.last_seen,
                    },
                )

        for raw in ctx.known_urls():
            canon = canonical_url(raw, target_host=target_host)
            if canon is None:
                continue
            seen.setdefault(
                canon.normalized,
                {
                    "url": canon.original,
                    "host": canon.host,
                    "path": canon.path,
                    "extension": canon.extension,
                    "status_code": None,
                    "source": "known_urls",
                    "first_seen": None,
                    "last_seen": None,
                },
            )

        historical_output = ctx.output_of("historical_intelligence")
        if historical_output is not None:
            for event in historical_output.historical:
                if event.asset_type is not AssetType.URL:
                    continue
                canon = canonical_url(event.value, target_host=target_host)
                if canon is None:
                    continue
                seen.setdefault(
                    canon.normalized,
                    {
                        "url": canon.original,
                        "host": canon.host,
                        "path": canon.path,
                        "extension": canon.extension,
                        "status_code": None,
                        "source": event.source,
                        "first_seen": event.first_seen,
                        "last_seen": event.last_seen,
                    },
                )

        by_type: dict[str, int] = {}
        archive_findings: list[tuple[str, bool, str]] = []
        for info in seen.values():
            doc_type = _DOC_TYPE_MAP.get((info["extension"] or "").lower())
            if doc_type is None:
                continue
            by_type[doc_type] = by_type.get(doc_type, 0) + 1

            if doc_type == "archive":
                confirmed = info["status_code"] == 200
                output.exposures.append(
                    ExposureRecord(
                        exposure_type="document",
                        url=info["url"],
                        observation_class="directly_retrievable" if confirmed else "indexed",
                        host=info["host"],
                        path=info["path"],
                        severity=Severity.INFORMATIONAL,
                        confidence=70 if confirmed else 45,
                        retrievable=confirmed,
                        sources=[info["source"]],
                        evidence={"document_type": doc_type},
                        first_seen=info["first_seen"],
                        last_seen=info["last_seen"],
                    )
                )
                # Archives surface as findings (this module has no dedicated
                # UI page, so findings are its only visibility). Severity
                # reflects verification: a 200-confirmed archive is worth a
                # closer look than an indexed-but-unfetched one.
                archive_findings.append((info["url"], confirmed, info["source"]))

        for url, confirmed, source in sorted(set(archive_findings)):
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.INDEXED_ARTIFACT,
                    severity=Severity.MEDIUM if confirmed else Severity.LOW,
                    title=f"Publicly reachable archive: {url.split('/')[-1] or url}",
                    description=(
                        f"{'Confirmed' if confirmed else 'Unverified'}: {url} "
                        f"appears to be a publicly reachable archive file. "
                        f"Archives are flagged because they are far likelier "
                        f"than documents to bundle content that was never "
                        f"meant for distribution. "
                        f"{'The archive returned HTTP 200 when fetched during the scan.'
                           if confirmed else
                           'The archive was not fetched - its existence is not confirmed.'} "
                        f"Metadata only - nothing was downloaded or inspected."
                    ),
                    recommendation=(
                        "Confirm the archive is intentionally public and does "
                        "not bundle credentials, backups, or internal data."
                    ),
                    location=url,
                    confidence=70 if confirmed else 45,
                    exposure=(
                        ExposureLevel.DIRECT if confirmed else ExposureLevel.INDEXED
                    ),
                    sources=[source],
                    evidence={
                        "document_type": "archive",
                        "verification": (
                            "verified_retrievable" if confirmed
                            else "unverified_pattern_match"
                        ),
                    },
                )
            )

        total_documents = sum(by_type.values())
        if total_documents:
            # One summary finding so the document inventory itself is visible
            # in the Findings tab even when no archive stands out.
            breakdown = ", ".join(
                f"{count} {dtype}" for dtype, count in sorted(by_type.items())
            )
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.INFORMATIONAL,
                    severity=Severity.INFORMATIONAL,
                    title=f"Document inventory: {total_documents} document/archive URLs catalogued",
                    description=(
                        f"Catalogued by extension from known URLs: {breakdown}. "
                        f"Metadata only - no document was downloaded or "
                        f"inspected."
                    ),
                    confidence=80,
                    exposure=ExposureLevel.INFERRED,
                    sources=["document_intelligence"],
                    evidence={"by_type": by_type},
                )
            )

        output.data["summary"] = {
            "by_type": by_type,
            "total_documents": total_documents,
            "archive_count": by_type.get("archive", 0),
        }
        return output
