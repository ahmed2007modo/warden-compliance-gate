"""Unit tests for diff parsing and tree comparison."""

from __future__ import annotations

import pytest
from app.adapters.terraform.diff import (
    build_pr_context_from_trees,
    compute_hunks,
    file_pair_from_trees,
    parse_unified_diff,
    validate_repo_path,
)
from app.core.errors import ValidationError


class TestValidateRepoPath:
    def test_accepts_plain_relative_path(self) -> None:
        assert validate_repo_path("infra/main.tf") == "infra/main.tf"

    def test_rejects_parent_traversal(self) -> None:
        with pytest.raises(ValidationError):
            validate_repo_path("../../etc/passwd")

    def test_rejects_absolute_path(self) -> None:
        with pytest.raises(ValidationError):
            validate_repo_path("/etc/passwd")

    def test_rejects_windows_drive(self) -> None:
        with pytest.raises(ValidationError):
            validate_repo_path("C:/secrets.tf")

    def test_normalizes_backslashes(self) -> None:
        assert validate_repo_path("infra\\main.tf") == "infra/main.tf"


class TestUnifiedDiff:
    def test_extracts_new_content(self) -> None:
        diff = (
            "diff --git a/main.tf b/main.tf\n"
            "--- a/main.tf\n"
            "+++ b/main.tf\n"
            "@@ -1,2 +1,2 @@\n"
            "-enabled = true\n"
            "+enabled = false\n"
        )
        result = parse_unified_diff(diff)
        assert "main.tf" in result
        assert "enabled = false" in result["main.tf"]

    def test_diff_too_large_rejected(self) -> None:
        with pytest.raises(ValidationError):
            parse_unified_diff("x" * 6_000_000)


class TestHunks:
    def test_detects_attribute_change(self) -> None:
        pair = file_pair_from_trees(
            "main.tf", 'enabled = "true"\nname = "x"\n', "main.tf", 'enabled = "false"\nname = "x"\n'
        )
        hunks = compute_hunks(pair)
        assert len(hunks) == 1
        assert any(line.startswith("-enabled") for line in hunks[0].lines)
        assert any(line.startswith("+enabled") for line in hunks[0].lines)


class TestTreeComparison:
    def test_docs_only_change_is_marked(self) -> None:
        ctx = build_pr_context_from_trees(
            "fixture", 1, "HEAD~1", "HEAD",
            {"README.md": "# Repo\n"},
            {"README.md": "# Repo\n\nupdated\n"},
        )
        assert len(ctx.changed_files) == 1
        assert ctx.changed_files[0].path == "README.md"

    def test_identical_trees_produce_no_changes(self) -> None:
        ctx = build_pr_context_from_trees(
            "fixture", 1, "HEAD~1", "HEAD",
            {"main.tf": "resource \"a\" \"b\" {}"},
            {"main.tf": "resource \"a\" \"b\" {}"},
        )
        assert ctx.changed_files == []

    def test_non_tf_non_md_files_filtered(self) -> None:
        ctx = build_pr_context_from_trees(
            "fixture", 1, "HEAD~1", "HEAD",
            {"script.sh": "echo hi\n"},
            {"script.sh": "echo bye\n", "main.tf": "x=1\n"},
        )
        assert [f.path for f in ctx.changed_files] == ["main.tf"]

    def test_unsafe_path_in_pr_rejected(self) -> None:
        with pytest.raises(ValidationError):
            build_pr_context_from_trees(
                "fixture", 1, "HEAD~1", "HEAD",
                {},
                {"../evil.tf": "x=1\n"},
            )
