"""Unit tests for the line-oriented HCL extractor and change extractor."""

from __future__ import annotations

from app.adapters.terraform.changes import extract_resource_changes
from app.adapters.terraform.hcl_parser import attribute_line, parse_hcl
from app.domain.types import ChangedFile

BASE_MAIN = '''resource "aws_cloudtrail" "audit_trail" {
  name           = "audit-trail"
  s3_bucket_name = "audit-artifacts-prod"
  enabled        = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_artifacts" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_iam_role_policy" "app_runtime" {
  name = "app_runtime"
  role = "app_runtime"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = "arn:aws:s3:::audit-artifacts-prod"
      }
    ]
  })
}
'''


def _pair(base: str, head: str) -> ChangedFile:
    return ChangedFile(
        path="main.tf",
        old_path="main.tf",
        change_type="modified",
        old_lines=tuple(base.splitlines()),
        new_lines=tuple(head.splitlines()),
    )


class TestParseHcl:
    def test_finds_all_resources(self) -> None:
        parsed = parse_hcl(BASE_MAIN, "main.tf")
        addresses = [(r.address.resource_type, r.address.resource_name) for r in parsed.resources]
        assert ("aws_cloudtrail", "audit_trail") in addresses
        assert ("aws_s3_bucket_server_side_encryption_configuration", "audit_artifacts") in addresses
        assert len(parsed.resources) == 3

    def test_attribute_line_numbers(self) -> None:
        parsed = parse_hcl(BASE_MAIN, "main.tf")
        trail = parsed.resources[0]
        assert attribute_line(trail, "enabled") == 4

    def test_multiline_value_collected(self) -> None:
        parsed = parse_hcl(BASE_MAIN, "main.tf")
        policy_res = parsed.resources[2]
        raw = policy_res.attributes["policy"]
        assert "jsonencode" in raw

    def test_unbalanced_input_flagged(self) -> None:
        parsed = parse_hcl('resource "aws_x" "y" {\n  a = "1"\n', "main.tf")
        assert parsed.unsupported == ["main.tf"]


class TestExtractChanges:
    def test_attribute_change_detected(self) -> None:
        head = BASE_MAIN.replace('enabled        = true', 'enabled        = false')
        changes = extract_resource_changes(_pair(BASE_MAIN, head))
        matches = [c for c in changes if c.attribute == "enabled"]
        assert len(matches) == 1
        change = matches[0]
        assert change.change_type == "attribute_changed"
        assert change.after == "false"
        assert change.file_path == "main.tf"
        assert change.line_no == 4

    def test_resource_deleted_detected(self) -> None:
        dropped = BASE_MAIN.replace(
            '''resource "aws_s3_bucket_server_side_encryption_configuration" "audit_artifacts" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
''',
            "",
        )
        changes = extract_resource_changes(_pair(BASE_MAIN, dropped))
        deleted = [c for c in changes if c.change_type == "resource_deleted"]
        assert len(deleted) == 1
        assert deleted[0].resource.resource_type == "aws_s3_bucket_server_side_encryption_configuration"

    def test_resource_added_detected(self) -> None:
        added = BASE_MAIN + 'resource "aws_docdb_cluster" "analytics" {\n  engine = "docdb"\n}\n'
        changes = extract_resource_changes(_pair(BASE_MAIN, added))
        added_changes = [c for c in changes if c.change_type == "resource_added"]
        assert len(added_changes) == 1
        assert added_changes[0].resource.resource_type == "aws_docdb_cluster"

    def test_wildcard_action_inside_multiline_policy(self) -> None:
        head = BASE_MAIN.replace('Action = ["s3:GetObject", "s3:ListBucket"]', 'Action = "*"')
        changes = extract_resource_changes(_pair(BASE_MAIN, head))
        policy = [c for c in changes if c.attribute == "policy"]
        assert len(policy) == 1
        assert '"*"' in str(policy[0].after) or "*" in str(policy[0].after)
