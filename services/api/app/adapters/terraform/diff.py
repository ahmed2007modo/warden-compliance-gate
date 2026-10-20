"""Git unified-diff parsing (read-only, no subprocess)."""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from app.core.errors import ValidationError
from app.domain.types import ChangedFile, Hunk, PullRequestContext


def _normalize(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def validate_repo_path(raw: str) -> str:
    """Reject path traversal, absolute paths and unsafe segments."""
    cleaned = raw.replace("\\", "/")
    if not cleaned or cleaned.startswith("/") or cleaned.startswith(":"):
        raise ValidationError(f"unsafe repo path: {raw!r}", code="path_unsafe")
    import re

    if re.match(r"^[A-Za-z]:", cleaned):
        raise ValidationError(f"absolute path rejected: {raw!r}", code="path_unsafe")
    segments = [segment for segment in cleaned.split("/") if segment not in ("", ".")]
    if any(segment == ".." for segment in segments):
        raise ValidationError(f"path traversal rejected: {raw!r}", code="path_unsafe")
    return "/".join(segments)


@dataclass
class FilePair:
    base_path: str
    head_path: str
    base_lines: tuple[str, ...]
    head_lines: tuple[str, ...]


def parse_unified_diff(diff_text: str) -> dict[str, str]:
    """Extract the new-side content of a unified diff keyed by head path."""
    if len(diff_text.encode("utf-8")) > 5_000_000:
        raise ValidationError("diff too large", code="diff_too_large")
    result: dict[str, str] = {}
    current_path: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        if current_path is not None:
            result[current_path] = "".join(buffer)

    for line in _normalize(diff_text).splitlines(keepends=True):
        if line.startswith("diff --git "):
            flush()
            current_path = None
            buffer = []
            continue
        if line.startswith("+++ "):
            current_path = line[4:].strip()
            if current_path.startswith("b/"):
                current_path = current_path[2:]
            continue
        if current_path is not None:
            buffer.append(line)
    flush()
    return result


def file_pair_from_trees(
    base_path: str,
    base_content: str,
    head_path: str,
    head_content: str,
) -> FilePair:
    return FilePair(
        base_path=base_path,
        head_path=head_path,
        base_lines=tuple(_normalize(base_content).splitlines()),
        head_lines=tuple(_normalize(head_content).splitlines()),
    )


def compute_hunks(file_pair: FilePair) -> tuple[Hunk, ...]:
    matcher = difflib.SequenceMatcher(
        a=file_pair.base_lines, b=file_pair.head_lines, autojunk=False
    )
    hunks: list[Hunk] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if i1 == i2 and j1 == j2:
            continue
        old_count = i2 - i1
        new_count = j2 - j1
        lines: list[str] = []
        for idx in range(max(old_count, new_count)):
            if idx < old_count and idx < new_count:
                if file_pair.base_lines[i1 + idx] != file_pair.head_lines[j1 + idx]:
                    lines.append(f"-{file_pair.base_lines[i1 + idx]}")
                    lines.append(f"+{file_pair.head_lines[j1 + idx]}")
                else:
                    lines.append(f" {file_pair.base_lines[i1 + idx]}")
            elif idx < old_count:
                lines.append(f"-{file_pair.base_lines[i1 + idx]}")
            else:
                lines.append(f"+{file_pair.head_lines[j1 + idx]}")
        merging = (
            hunks
            and hunks[-1].old_start + hunks[-1].old_count == i1 + 1
            and hunks[-1].new_start + hunks[-1].new_count == j1 + 1
        )
        if merging:
            previous = hunks[-1]
            hunks[-1] = Hunk(
                old_start=previous.old_start,
                old_count=old_count + previous.old_count,
                new_start=previous.new_start,
                new_count=new_count + previous.new_count,
                lines=previous.lines + tuple(lines),
            )
        else:
            hunks.append(
                Hunk(
                    old_start=i1 + 1,
                    old_count=old_count,
                    new_start=j1 + 1,
                    new_count=new_count,
                    lines=tuple(lines),
                )
            )
    return tuple(hunks)


def build_pr_context_from_trees(
    repository: str,
    pr_number: int,
    base_ref: str,
    head_ref: str,
    base_tree: dict[str, str],
    head_tree: dict[str, str],
    pr_description: str = "",
) -> PullRequestContext:
    """Compare two file trees into one validated PR context (all `.tf` and .md files)."""
    if len(head_tree) > 200 or len(base_tree) > 200:
        raise ValidationError("too many files", code="too_many_files")
    all_paths = sorted(set(base_tree) | set(head_tree))
    changed: list[ChangedFile] = []
    for path in all_paths:
        safe = validate_repo_path(path)
        old = base_tree.get(path, "")
        new = head_tree.get(path, "")
        if old == new:
            continue
        if path.rsplit(".", 1)[-1] not in ("tf", "tfvars", "md"):
            continue
        change_type = (
            "added" if path not in base_tree
            else "deleted" if path not in head_tree
            else "modified"
        )
        pair = file_pair_from_trees(path, old, path, new)
        changed.append(
            ChangedFile(
                path=safe,
                old_path=safe,
                change_type=change_type,
                old_lines=pair.base_lines,
                new_lines=pair.head_lines,
                hunks=compute_hunks(pair),
            )
        )
    return PullRequestContext(
        repository=repository,
        pr_number=pr_number,
        base_ref=base_ref,
        head_ref=head_ref,
        changed_files=changed,
        pr_description=pr_description,
    )
