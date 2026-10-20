"""Architecture boundary tests: analysis layer cannot import api/db layers."""

from __future__ import annotations

import ast
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[2] / "services" / "api" / "app"

ALLOWED_IMPORTS: dict[str, set[str]] = {
    "app.adapters": {"app.domain", "app.core"},
    "app.graph": {"app.domain", "app.core"},
    "app.policies": {"app.domain", "app.core"},
    "app.analysis": {"app.adapters", "app.graph", "app.policies", "app.domain", "app.core"},
}


def _imports_of(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return set()
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


class TestArchitecture:
    def test_inner_layers_do_not_reach_upward(self) -> None:
        violations: list[str] = []
        for module_name, allowed in ALLOWED_IMPORTS.items():
            root = API_DIR / module_name.split(".", 1)[1]
            if not root.exists():
                continue
            for file in root.rglob("*.py"):
                for imported in _imports_of(file):
                    if not imported.startswith("app."):
                        continue
                    if any(imported == allowed_module or imported.startswith(allowed_module + ".")
                           for allowed_module in allowed | {module_name}):
                        continue
                    violations.append(f"{file.relative_to(API_DIR)} imports {imported}")
        assert not violations, "\n".join(violations)
