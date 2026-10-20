"""Dependency-free line-oriented HCL block extractor used by the native rule engine.

Scope (documented): `resource` and `data` blocks at file top level with flat attribute
values, inline maps/lists, nested attribute blocks (`ingress { ... }`), and multi-line call
expressions such as `policy = jsonencode({...})`. Each multi-line value or nested block is
captured as one raw string under its attribute name with the first line number, so rules can
match on text and the report can cite file:line provenance.

Brace depth is tracked globally (independent of buffers) so an intermediate `}` inside a
nested block never closes the enclosing resource prematurely.

Out of scope (surfaced as unsupported constructs): heredocs spanning many lines,
interpolations with unbalanced braces inside strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from app.domain.types import ResourceAddress, ResourceSnapshot

BLOCK_START = re.compile(r'^\s*(resource|data)\s+"([a-zA-Z0-9_-]+)"\s+"([a-zA-Z0-9_-]+)"\s*\{')
ATTRIBUTE = re.compile(r'^\s*"?([A-Za-z_][A-Za-z0-9_]*)"?\s*=\s*(.*)$')

_OPEN_CHARS = "{["
_CLOSE_CHARS = "}]"


@dataclass
class ParsedFile:
    path: str
    resources: list[ResourceSnapshot] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


def _strip_inline_comment(raw: str) -> str:
    out: list[str] = []
    in_string = False
    idx = 0
    while idx < len(raw):
        char = raw[idx]
        if in_string:
            if char == "\\":
                idx += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "#":
            break
        out.append(char)
        idx += 1
    return "".join(out).strip()


def _module_dir(path: str) -> str:
    parent = PurePosixPath(path).parent
    if str(parent) == ".":
        return ""
    return str(parent)


def _delta(text: str) -> int:
    return sum(1 for ch in text if ch in _OPEN_CHARS) - sum(1 for ch in text if ch in _CLOSE_CHARS)


def _clean_single(raw: str) -> str:
    value = raw.strip().rstrip(",").strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


class _Block:
    """Mutable accumulator for one `resource`/`data` block."""

    def __init__(self, mode: str, rtype: str, rname: str) -> None:
        self.mode = mode
        self.rtype = rtype
        self.rname = rname
        self.attributes: dict[str, str] = {}
        self.lines: dict[str, int] = {}
        self.buffer_name: str | None = None
        self.buffer_depth: int = 0
        self.buffer_start: int = 0
        self.buffer: list[str] = []

    def start_buffer(self, name: str, line_delta: int, line_no: int, first_line: str) -> None:
        if self.buffer_name is not None:
            return  # already collecting; stay on the previous buffer
        self.buffer_name = name
        self.buffer_depth = line_delta
        self.buffer_start = line_no
        self.buffer = [first_line]

    def feed_line(self, stripped: str, line_delta: int) -> bool:
        if self.buffer_name is None:
            return False
        self.buffer.append(stripped)
        self.buffer_depth += line_delta
        if self.buffer_depth <= 0:
            self.finish_buffer()
        return True

    def finish_buffer(self) -> None:
        name = self.buffer_name
        if name is None:
            return
        start = self.buffer_start
        payload = "\n".join(self.buffer).strip()
        self.buffer_name = None
        self.buffer_depth = 0
        self.buffer_start = 0
        self.buffer = []
        if name in self.attributes or not payload:
            return
        self.attributes[name] = payload
        self.lines[name] = start


def parse_hcl(content: str, path: str) -> ParsedFile:
    parsed = ParsedFile(path=path)
    depth = 0
    active: _Block | None = None

    def flush() -> None:
        nonlocal active
        if active is None:
            return
        active.finish_buffer()
        snapshot = ResourceSnapshot(
            address=ResourceAddress(resource_type=active.rtype, resource_name=active.rname),
            file_path=path,
            attributes={**active.attributes, "__lines__": dict(active.lines)},
            mode=active.mode,
            module=_module_dir(path),
        )
        parsed.resources.append(snapshot)
        active = None

    for line_no, raw in enumerate(content.splitlines(), start=1):
        stripped = _strip_inline_comment(raw)
        if not stripped:
            continue
        if stripped.startswith("#"):
            parsed.comments.append(stripped.lstrip("#").strip())
            continue

        pre_depth = depth
        depth += _delta(stripped)
        if depth < 0:
            depth = 0

        if pre_depth == 0:
            block = BLOCK_START.match(stripped)
            if block:
                mode, rtype, rname = block.groups()
                flush()  # close a dangling active block, if any
                active = _Block(mode, rtype, rname)
                continue
            continue  # top-level terraform/provider/variable blocks are out of scope

        if active is None:
            continue

        if depth == 0:  # resource block's closing brace
            flush()
            continue

        if active.buffer_name is not None:
            active.feed_line(stripped, _delta(stripped))
            continue

        matched = ATTRIBUTE.match(stripped)
        if matched is not None:
            name, value = matched.group(1), matched.group(2).strip()
            delta = _delta(stripped)
            if delta != 0:
                active.start_buffer(name, delta, line_no, stripped)
            elif name not in active.attributes:
                active.attributes[name] = _clean_single(value)
                active.lines[name] = line_no
            continue

        header = stripped.split()[0] if stripped.split() else ""
        if header and _delta(stripped) > 0 and header not in active.attributes:
            active.start_buffer(header, _delta(stripped), line_no, stripped)
            continue

    if active is not None and depth > 0:
        parsed.unsupported.append(path)
    flush()
    return parsed


def attribute_line(snapshot: ResourceSnapshot, attribute: str) -> int | None:
    """Head-side line number for one flat attribute (or nested block header)."""
    lines = snapshot.attributes.get("__lines__")
    if isinstance(lines, dict):
        value = lines.get(attribute)
        if isinstance(value, int):
            return value
    return None
