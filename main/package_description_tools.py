"""Two ways to get an npm package's description, exposed as agent tools.

Used during stage 1 dependency triage: `stage1_characterize.classify_dependencies`
tags every dependency 'curated' (in main/auth_taxonomy.json) or 'heuristic' (matched
only by a keyword regex, category unknown). For a 'heuristic' package, the agent can
call one of these tools to read its actual description before deciding whether it is
really auth-related, instead of guessing from the package name alone.

Two sources, because they cover different situations:
  - local:    reads node_modules/<pkg>/package.json — exact installed version, works
              offline, but only if `npm install` has already been run.
  - registry: fetches from registry.npmjs.org — works even if the package is only
              listed in package.json and not yet installed (e.g. an uninstalled
              devDependency), and returns npm's own description, not ours.

Same BaseTool + pydantic args_schema shape as fetch_url_tool.FetchURLTool, so both
plug into create_deep_agent(tools=[...]) the same way.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Type

import httpx
from langchain_core.callbacks.manager import CallbackManagerForToolRun
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

REGISTRY_TIMEOUT_SECONDS = 5.0


class LocalPackageDescriptionInput(BaseModel):
    package_name: str = Field(description="npm package name exactly as it appears in package.json")
    project_root: str = Field(description="absolute path to the directory containing node_modules")


class LocalPackageDescriptionTool(BaseTool):
    name: str = "local_package_description"
    description: str = (
        "Read a package's description from its installed node_modules/<pkg>/package.json. "
        "Exact installed version, no network call. Returns found=False if the package "
        "isn't installed locally — try registry_package_description instead."
    )
    args_schema: Type[LocalPackageDescriptionInput] = LocalPackageDescriptionInput

    def _run(
        self,
        package_name: str,
        project_root: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        pkg_path = Path(project_root) / "node_modules" / package_name / "package.json"
        if not pkg_path.exists():
            return json.dumps({"found": False, "package": package_name, "source": "local"})

        try:
            data = json.loads(pkg_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return json.dumps({"found": False, "package": package_name, "source": "local", "error": str(exc)})

        return json.dumps(
            {
                "found": True,
                "package": package_name,
                "source": "local",
                "installed_version": data.get("version", ""),
                "description": data.get("description", ""),
                "keywords": data.get("keywords", []),
            }
        )


class RegistryPackageDescriptionInput(BaseModel):
    package_name: str = Field(description="npm package name to look up on the public npm registry")


class RegistryPackageDescriptionTool(BaseTool):
    name: str = "registry_package_description"
    description: str = (
        "Fetch a package's description from the public npm registry (registry.npmjs.org). "
        "Works even if the package isn't installed locally. Returns found=False on a "
        "network error or unknown package name."
    )
    args_schema: Type[RegistryPackageDescriptionInput] = RegistryPackageDescriptionInput

    def _run(
        self,
        package_name: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        try:
            resp = httpx.get(
                f"https://registry.npmjs.org/{package_name}/latest",
                timeout=REGISTRY_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            return json.dumps({"found": False, "package": package_name, "source": "registry", "error": str(exc)})

        if resp.status_code != 200:
            return json.dumps(
                {"found": False, "package": package_name, "source": "registry", "status_code": resp.status_code}
            )

        data = resp.json()
        return json.dumps(
            {
                "found": True,
                "package": package_name,
                "source": "registry",
                "latest_version": data.get("version", ""),
                "description": data.get("description", ""),
                "keywords": data.get("keywords", []),
            }
        )
