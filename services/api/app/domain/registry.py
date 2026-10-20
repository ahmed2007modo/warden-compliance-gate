"""Loads framework/control/evidence registries from the JSON sources."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from app.core.errors import ConfigurationError
from app.domain.types import Control, Evidence

_FRAMEWORK_FILES = ("iso-27001.json", "soc2.json", "nis2.json", "cra.json")


def _read_json(path: Path) -> dict:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"registry file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"invalid JSON in {path}: {exc}") from exc


class ControlRegistry:
    """In-memory 'map once' control set with per-framework mappings."""

    def __init__(self, base_dir: str | Path) -> None:
        base = Path(base_dir)
        shared = base / "shared-controls.json"
        payload = _read_json(shared)
        self.controls: dict[str, Control] = {}
        for raw in payload.get("controls", []):
            control = Control(
                control_id=raw["control_id"],
                title=raw["title"],
                objective=raw["objective"],
                requirement_summary=raw["requirement_summary"],
                evidence_expected=tuple(raw.get("evidence_expected", ())),
            )
            self.controls[control.control_id] = control
        self.mappings: dict[str, dict[str, dict[str, str]]] = {}
        for filename in _FRAMEWORK_FILES:
            data = _read_json(base / filename)
            framework_id = data["framework_id"]
            self.mappings[framework_id] = {
                mapping["ref"]: {
                    "control_id": mapping["control_id"],
                    "requirement_text": mapping["requirement_text"],
                }
                for mapping in data.get("mappings", [])
            }

    def controls_for(self, control_id: str) -> Control | None:
        return self.controls.get(control_id)

    def refs_for_control(self, control_id: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for framework_id, refs in self.mappings.items():
            for ref, payload in refs.items():
                if payload["control_id"] == control_id:
                    out.append((framework_id, ref))
        return out

    def all_controls(self) -> list[Control]:
        return list(self.controls.values())


class EvidenceRegistry:
    """Canonical set of collected evidence with provenance."""

    def __init__(self, base_dir: str | Path) -> None:
        payload = _read_json(Path(base_dir) / "evidence-seed.json")
        self.evidence: dict[str, Evidence] = {}
        for raw in payload.get("evidence", []):
            item = Evidence(
                evidence_id=raw["evidence_id"],
                control_id=raw["control_id"],
                source=raw["source"],
                source_location=raw["source_location"],
                collected_at=datetime.fromisoformat(raw["collected_at"].replace("Z", "+00:00")),
                resource_refs=tuple(raw.get("resource_refs", ())),
                content_hash=raw["content_hash"],
                evidence_type=raw["evidence_type"],
                age_days=int(raw.get("age_days", 0)),
                freshness_status=raw["freshness_status"],
                provenance=raw.get("provenance", ""),
                verification_status=raw.get("verification_status", "verified"),
            )
            self.evidence[item.evidence_id] = item

    def get(self, evidence_id: str) -> Evidence | None:
        return self.evidence.get(evidence_id)

    def all(self) -> list[Evidence]:
        return list(self.evidence.values())

    def for_control(self, control_id: str) -> list[Evidence]:
        return [item for item in self.evidence.values() if item.control_id == control_id]
