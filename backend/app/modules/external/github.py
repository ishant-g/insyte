"""GitHub Intelligence.

Public code and repositories mentioning the target are some of the most
consequential recon evidence Insyte can find - a leaked internal hostname
in a config committed to a public repo, or an infrastructure-as-code file
that documents the target's own architecture. This module only catalogues
what its providers already found; it never clones, downloads, or
otherwise acts on a repository. The GitHub API provider needs a token,
but the grep.app provider is keyless, so the module still produces
code-search observations with zero credentials configured.
"""

from __future__ import annotations

from app.core.contracts import AssetRecord, ModuleOutput
from app.core.target import TargetType, is_subdomain_of
from app.models.enums import AssetType, ModuleCategory, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext


class GitHubIntelligenceModule(IntelligenceModule):
    id = "github_intelligence"
    name = "GitHub Intelligence"
    description = (
        "Searches public GitHub repositories and code for references to "
        "the target. Read-only cataloguing of what is already public - "
        "Insyte never authenticates with, uses, or acts on anything it "
        "discovers. The GitHub API path needs a token; without one the "
        "module still collects keyless grep.app code mentions."
    )
    category = ModuleCategory.EXTERNAL
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    providers = ("github", "grepapp")
    requires_api_key = False
    timeout = 45.0
    order = 48

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target_registrable = ctx.target.registrable or ctx.target.value

        repo_observations, repo_statuses = self.gather(ctx, "repositories", limit=30)
        output.providers.extend(repo_statuses)

        # The GitHub provider's "urls" intent runs its code-search path
        # (`GitHubProvider._search_code`), not archive-style URL discovery
        # - it also yields REPOSITORY and, incidentally, SUBDOMAIN
        # observations from hostnames referenced in matched code.
        code_observations, code_statuses = self.gather(ctx, "urls", limit=50)
        output.providers.extend(code_statuses)

        seen_repos: set[str] = set()
        for observation in repo_observations + code_observations:
            if observation.asset_type is not AssetType.REPOSITORY:
                continue
            if observation.value in seen_repos:
                continue
            seen_repos.add(observation.value)
            output.assets.append(
                AssetRecord(
                    asset_type=AssetType.REPOSITORY,
                    value=observation.value,
                    confidence=observation.confidence,
                    sources=[observation.source],
                    evidence=observation.evidence,
                    attributes=observation.attributes,
                    first_seen=observation.first_seen,
                    last_seen=observation.last_seen,
                )
            )

        for observation in code_observations:
            if observation.asset_type is AssetType.SUBDOMAIN and is_subdomain_of(
                observation.value, target_registrable
            ):
                output.observations.append(observation)

        languages: dict[str, int] = {}
        starred = 0
        for asset in output.assets:
            language = asset.attributes.get("language")
            if language:
                languages[language] = languages.get(language, 0) + 1
            stars = asset.attributes.get("stars") or 0
            if isinstance(stars, (int, float)) and stars > 100:
                starred += 1

        output.data["summary"] = {
            "repository_count": len(output.assets),
            "top_languages": sorted(languages.items(), key=lambda kv: -kv[1])[:10],
            "starred_repository_count": starred,
        }
        return output
