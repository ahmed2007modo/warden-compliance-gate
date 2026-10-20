"""Terraform change extractor: diff ResourceSnapshots into typed AttributeChanges."""

from __future__ import annotations

from app.domain.types import AttributeChange, ChangedFile, ResourceSnapshot

RESERVED_KEYS = ("__lines__",)


def flatten_resource_address(snapshot: ResourceSnapshot) -> str:
    prefix = "data." if snapshot.mode == "data" else ""
    module = f"module.{snapshot.module}." if snapshot.module else ""
    return f"{module}{prefix}{snapshot.address.resource_type}.{snapshot.address.resource_name}"


def _semantic_attributes(snapshot: ResourceSnapshot) -> dict[str, object]:
    return {
        key: value
        for key, value in snapshot.attributes.items()
        if not key.startswith("__")
    }


def extract_resource_changes(file: ChangedFile) -> list[AttributeChange]:
    """Extract attribute-level changes for one Terraform file from base→head."""
    from app.adapters.terraform.hcl_parser import parse_hcl

    if not file.path.endswith(".tf"):
        return []
    base_content = "".join(line + "\n" for line in file.old_lines)
    head_content = "".join(line + "\n" for line in file.new_lines)
    base_parsed = parse_hcl(base_content, file.path)
    head_parsed = parse_hcl(head_content, file.path)
    return _diff_resources(base_parsed.resources, head_parsed.resources, file)


def _diff_resources(
    base: list[ResourceSnapshot],
    head: list[ResourceSnapshot],
    file: ChangedFile,
) -> list[AttributeChange]:
    changes: list[AttributeChange] = []
    head_by_addr = {flatten_resource_address(r): r for r in head}
    base_by_addr = {flatten_resource_address(r): r for r in base}

    for addr, head_res in head_by_addr.items():
        if addr not in base_by_addr:
            changes.append(
                AttributeChange(
                    resource=head_res.address,
                    attribute=None,
                    before=None,
                    after=_summarize(head_res),
                    change_type="resource_added",
                    file_path=file.path,
                    line_no=None,
                )
            )
            continue
        changes.extend(_diff_attributes(base_by_addr[addr], head_res, file.path))

    for addr, base_res in base_by_addr.items():
        if addr not in head_by_addr:
            changes.append(
                AttributeChange(
                    resource=base_res.address,
                    attribute=None,
                    before=_summarize(base_res),
                    after=None,
                    change_type="resource_deleted",
                    file_path=file.path,
                    line_no=None,
                )
            )
    return changes


def _diff_attributes(
    base_res: ResourceSnapshot,
    head_res: ResourceSnapshot,
    file_path: str,
) -> list[AttributeChange]:
    from app.adapters.terraform.hcl_parser import attribute_line

    base_attrs = _semantic_attributes(base_res)
    head_attrs = _semantic_attributes(head_res)
    changes: list[AttributeChange] = []
    for attr in sorted(set(base_attrs) | set(head_attrs)):
        before = base_attrs.get(attr)
        after = head_attrs.get(attr)
        if _equivalent(before, after):
            continue
        if before is None:
            change_type = "attribute_added"
        elif after is None:
            change_type = "attribute_removed"
        else:
            change_type = "attribute_changed"
        changes.append(
            AttributeChange(
                resource=head_res.address,
                attribute=attr,
                before=before,
                after=after,
                change_type=change_type,
                file_path=file_path,
                line_no=attribute_line(head_res, attr),
            )
        )
    return changes


def _equivalent(a: object, b: object) -> bool:
    return _normalize_value(a) == _normalize_value(b)


def _normalize_value(value: object) -> object:
    """Collapse cosmetic whitespace so only semantic differences survive the diff."""
    if isinstance(value, str):
        cleaned_lines = [
            line.strip().rstrip(",")
            for line in value.replace("\r\n", "\n").split("\n")
            if line.strip()
        ]
        cleaned = " ".join(cleaned_lines)
        if len(cleaned) >= 2 and cleaned[0] == '"' and cleaned[-1] == '"':
            cleaned = cleaned[1:-1]
        return cleaned
    if isinstance(value, dict):
        return {k: _normalize_value(v) for k, v in sorted(value.items()) if not k.startswith("__")}
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    return value


def _summarize(snapshot: ResourceSnapshot) -> dict[str, object]:
    return {
        "address": str(snapshot.address),
        "mode": snapshot.mode,
        "keys": sorted(_semantic_attributes(snapshot)),
    }
