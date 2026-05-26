"""
Detection pack helpers for SigmaHQ folder-based rule assignment.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, Iterable, Optional, Tuple

import requests


@dataclass(frozen=True)
class DetectionPackDefinition:
    name: str
    directory_glob: str
    description: str
    tags: Tuple[str, ...] = ()

    def matches(self, repo_relative_path: str) -> bool:
        normalized_path = PurePosixPath(repo_relative_path).as_posix()
        return fnmatch.fnmatch(normalized_path, self.directory_glob)
    
    @property
    def real_name(self) -> str:
        return '[SigmaHQ] ' + self.name


PACK_DEFINITIONS: Tuple[DetectionPackDefinition, ...] = (
    DetectionPackDefinition(
        name="Rules Application",
        directory_glob="rules/application/*",
        description=(
            "Detection rules focused on application-level activity such as databases, "
            "middleware, productivity tools, enterprise software, and SaaS applications."
        ),
        tags=("application",),
    ),
    DetectionPackDefinition(
        name="Rules Cloud",
        directory_glob="rules/cloud/*",
        description=(
            "Detection rules for cloud platforms and services including AWS, Azure, GCP, "
            "Microsoft 365, Okta, and other cloud-native telemetry sources."
        ),
        tags=("cloud",),
    ),
    DetectionPackDefinition(
        name="Rules Category",
        directory_glob="rules/category/*",
        description=(
            "Rules organized by generic log or event categories such as process creation, "
            "authentication, DNS, proxy, firewall, registry, and file events."
        ),
        tags=("category",),
    ),
    DetectionPackDefinition(
        name="Rules Identity",
        directory_glob="rules/identity/*",
        description=(
            "Detection rules targeting identity systems, authentication services, privilege "
            "escalation, account abuse, and identity provider telemetry."
        ),
        tags=("identity",),
    ),
    DetectionPackDefinition(
        name="Rules Linux",
        directory_glob="rules/linux/*",
        description=(
            "Linux-specific detection rules covering system logs, process activity, "
            "persistence, privilege escalation, and attacker behavior on Linux systems."
        ),
        tags=("linux",),
    ),
    DetectionPackDefinition(
        name="Rules MacOS",
        directory_glob="rules/macos/*",
        description=(
            "macOS-focused detection rules for Apple endpoint telemetry, persistence "
            "mechanisms, execution artifacts, and suspicious system activity."
        ),
        tags=("macos",),
    ),
    DetectionPackDefinition(
        name="Rules Network",
        directory_glob="rules/network/*",
        description=(
            "Network-centric detection rules for IDS, firewall, proxy, DNS, VPN, and "
            "traffic-analysis related telemetry."
        ),
        tags=("network",),
    ),
    DetectionPackDefinition(
        name="Rules Web",
        directory_glob="rules/web/*",
        description=(
            "Detection rules related to web servers, web applications, HTTP activity, and "
            "web-based attack patterns."
        ),
        tags=("web",),
    ),
    DetectionPackDefinition(
        name="Rules Windows",
        directory_glob="rules/windows/*",
        description=(
            "Windows-specific detection rules covering Sysmon, Event Logs, PowerShell, "
            "Active Directory, Defender, and common attacker techniques on Windows hosts."
        ),
        tags=("windows",),
    ),
    DetectionPackDefinition(
        name="Threat Hunting Cloud",
        directory_glob="rules-threat-hunting/cloud/*",
        description=(
            "Broad cloud hunting queries intended to help analysts investigate suspicious "
            "or anomalous cloud behavior rather than generate high-confidence alerts."
        ),
        tags=("threat-hunting", "cloud"),
    ),
    DetectionPackDefinition(
        name="Threat Hunting Linux",
        directory_glob="rules-threat-hunting/linux/*",
        description=(
            "Linux threat hunting rules designed for exploratory analysis and identification "
            "of suspicious behaviors requiring analyst review."
        ),
        tags=("threat-hunting", "linux"),
    ),
    DetectionPackDefinition(
        name="Threat Hunting MacOS",
        directory_glob="rules-threat-hunting/macos/*",
        description=(
            "macOS threat hunting rules that support proactive investigations into "
            "potentially malicious or unusual endpoint activity."
        ),
        tags=("threat-hunting", "macos"),
    ),
    DetectionPackDefinition(
        name="Threat Hunting Network",
        directory_glob="rules-threat-hunting/network/*",
        description=(
            "Network threat hunting rules intended to surface anomalous traffic patterns, "
            "lateral movement, reconnaissance, or suspicious communications."
        ),
        tags=("threat-hunting", "network"),
    ),
    DetectionPackDefinition(
        name="Threat Hunting Web",
        directory_glob="rules-threat-hunting/web/*",
        description=(
            "Threat hunting rules for identifying suspicious web requests, exploitation "
            "attempts, or abnormal web application behavior."
        ),
        tags=("threat-hunting", "web"),
    ),
    DetectionPackDefinition(
        name="Threat Hunting Windows",
        directory_glob="rules-threat-hunting/windows/*",
        description=(
            "Windows hunting rules aimed at uncovering suspicious endpoint and user "
            "activity that may indicate attacker presence or post-exploitation behavior."
        ),
        tags=("threat-hunting", "windows"),
    ),
    DetectionPackDefinition(
        name="Emerging Threats",
        directory_glob="rules-emerging-threats/*",
        description=(
            "Time-sensitive rules focused on newly observed malware, campaigns, CVEs, "
            "zero-days, and active threat actor techniques."
        ),
        tags=("emerging-threats",),
    ),
    DetectionPackDefinition(
        name="Compliance",
        directory_glob="rules-compliance/*",
        description=(
            "Rules aligned to security and compliance frameworks such as CIS Controls, "
            "NIST, ISO 27001, PCI-DSS, and audit-related monitoring requirements."
        ),
        tags=("compliance",),
    ),
)


def _normalize_name(name: str) -> str:
    return name.strip().casefold()


def find_detection_pack_for_path(
    repo_relative_path: str,
) -> Optional[DetectionPackDefinition]:
    for definition in PACK_DEFINITIONS:
        if definition.matches(repo_relative_path):
            return definition
    return None


class DetectionPackManager:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._packs_by_name: Dict[str, str] = {}
        self._fetched_existing_packs = False

    @property
    def _headers(self) -> Dict[str, str]:
        return {"API-KEY": self.api_key, "Content-Type": "application/json"}

    def _cache_pack(self, pack: Dict):
        pack_name = pack["name"]
        pack_id = pack["id"]
        if not pack_name or not pack_id:
            return
        self._packs_by_name[_normalize_name(pack_name)] = str(pack_id)

    def refresh_existing_packs(self) -> Dict[str, str]:
        if self._fetched_existing_packs:
            return dict(self._packs_by_name)

        page = 1
        while True:
            response = requests.get(
                f"{self.base_url}/v1/detection-packs/",
                headers=self._headers,
                params={
                    "labels": "sigmahq",
                    "show_only_my_detection_packs": "true",
                    "page": page,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            results = data.get("results", [])
            if not results:
                break

            for pack in results:
                self._cache_pack(pack)

            total_results_count = data.get("total_results_count", 0)
            if len(self._packs_by_name) >= total_results_count:
                break
            page += 1

        self._fetched_existing_packs = True
        return dict(self._packs_by_name)

    def _create_detection_pack(self, definition: DetectionPackDefinition) -> Dict:
        base_payload = {
            "name": definition.real_name,
            "description": definition.description,
            "tlp_level": "clear",
            "labels": ["osint", "sigmahq", *definition.tags],
        }

        response = requests.post(
            f"{self.base_url}/v1/detection-packs/",
            headers=self._headers,
            json=base_payload,
            timeout=self.timeout,
        )
        if not response.ok:
            raise RuntimeError(
                f"Failed to create detection pack '{definition.real_name}': "
                f"{response.status_code} {response.text}"
            )
        pack = response.json()
        self._cache_pack(pack)
        return pack

    def get_or_create_pack_id(self, definition: DetectionPackDefinition) -> str:
        self.refresh_existing_packs()
        existing_pack_id = self._packs_by_name.get(_normalize_name(definition.real_name))
        if existing_pack_id:
            return existing_pack_id

        created_pack = self._create_detection_pack(definition)
        return str(created_pack["id"])

    def add_rules_to_pack(
        self, detection_pack_id: str, rule_ids: Iterable[str]
    ) -> requests.Response:
        payload = {"rule_ids": list(rule_ids)}
        response = requests.post(
            f"{self.base_url}/v1/detection-packs/{detection_pack_id}/add-rules/",
            headers=self._headers,
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response
