"""
Unit tests for the AWS Config tagging compliance Lambda handler.

Tests cover:
- Resource parsing
- Evaluation against YAML policy from S3
- Compliance type mapping
- Lambda handler integration
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

import handler
from engine import Account, Outcome, Subject, Violation
from policy import Policy, PolicyError
from store import Mappings

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_resource():
    """A sample Resource for testing."""
    return handler.Resource(
        ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-0abcd1234efgh5678",
        AccountId="123456789012",
        ResourceType="AWS::EC2::Instance",
        ResourceId="i-0abcd1234efgh5678",
        Tags={
            "Environment": "Production",
            "CostCenter": "12345",
            "Owner": "team@example.com",
        },
    )


@pytest.fixture
def sample_config_event():
    """A sample AWS Config event payload."""
    return {
        "version": "1.0",
        "invokingEvent": json.dumps(
            {
                "configurationItem": {
                    "configurationItemCaptureTime": "2026-02-07T12:00:00.000Z",
                    "configurationItemStatus": "ResourceDiscovered",
                    "resourceType": "AWS::EC2::Instance",
                    "resourceId": "i-0abcd1234efgh5678",
                    "resourceName": "my-ec2-instance",
                    "awsRegion": "eu-west-2",
                    "awsAccountId": "123456789012",
                    "ARN": "arn:aws:ec2:eu-west-2:123456789012:instance/i-0abcd1234efgh5678",
                    "tags": {
                        "Environment": "Production",
                        "CostCenter": "12345",
                        "Owner": "team@example.com",
                    },
                },
                "messageType": "ConfigurationItemChangeNotification",
            }
        ),
        "ruleParameters": "{}",
        "resultToken": "test-result-token-12345",
        "eventLeftScope": False,
        "executionRoleArn": "arn:aws:iam::123456789012:role/config-role",
        "configRuleArn": "arn:aws:config:eu-west-2:123456789012:config-rule/tagging-compliance",
        "configRuleName": "tagging-compliance",
        "configRuleId": "config-rule-abc123",
        "accountId": "123456789012",
    }


@pytest.fixture
def sample_policy():
    """A sample Policy for testing."""
    return Policy(exclude_resource_types=frozenset(), rules=())


@pytest.fixture
def sample_mappings():
    """A sample Mappings for testing."""
    return Mappings(
        to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
        to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
    )


@pytest.fixture
def sample_inventory():
    """A sample inventory for testing."""
    return {
        "123456789012": Account(
            account_id="123456789012",
            name="test-account",
            ou_path="root/test",
            status="ACTIVE",
            tags={"Environment": "Production"},
        )
    }


# ============================================================================
# Tests for Resource class methods
# ============================================================================


class TestResource:
    """Tests for the Resource class."""

    def test_parse_valid_configuration_item(self):
        """Test parsing a valid configuration item."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0abcd1234efgh5678",
            "ARN": "arn:aws:ec2:eu-west-2:123456789012:instance/i-0abcd1234efgh5678",
            "configuration": {
                "instanceId": "i-0abcd1234efgh5678",
                "tags": [
                    {"key": "Environment", "value": "Production"},
                    {"key": "Name", "value": "test-instance"},
                ],
            },
        }
        resource = handler.Resource.parse(item)
        assert (
            resource.ARN
            == "arn:aws:ec2:eu-west-2:123456789012:instance/i-0abcd1234efgh5678"
        )
        assert resource.AccountId == "123456789012"
        assert resource.ResourceType == "AWS::EC2::Instance"
        assert resource.ResourceId == "i-0abcd1234efgh5678"
        assert resource.Tags["Environment"] == "Production"

    def test_parse_configuration_item_missing_field(self):
        """Test parsing fails when required field is missing."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            # Missing resourceId
            "configuration": {"tags": []},
        }
        with pytest.raises(ValueError, match="missing required field"):
            handler.Resource.parse(item)

    def test_parse_configuration_item_no_arn(self):
        """Test parsing when the ARN field is absent."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0abcd1234",
            # Missing ARN
            "configuration": {"tags": []},
        }
        resource = handler.Resource.parse(item)
        assert resource.ARN == ""
        assert resource.ResourceId == "i-0abcd1234"

    def test_parse_configuration_item_null_arn(self):
        """Test parsing when ARN is null, as sent for deleted resources."""
        item = {
            "awsAccountId": "291216788061",
            "resourceType": "AWS::Lambda::Function",
            "resourceId": "lz-instance-scheduler",
            "ARN": None,
            "configuration": None,
            "configurationItemStatus": "ResourceDeleted",
        }
        resource = handler.Resource.parse(item)
        assert resource.ARN == ""
        assert resource.ResourceType == "AWS::Lambda::Function"
        assert resource.Tags == {}

    def test_parse_configuration_item_top_level_tags(self):
        """Test parsing tags from the top level 'tags' map on the configuration item."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::S3::Bucket",
            "resourceId": "my-bucket",
            "ARN": "arn:aws:s3:::my-bucket",
            "tags": {"Environment": "Production", "Owner": "team@example.com"},
            "configuration": {"name": "my-bucket"},
        }
        resource = handler.Resource.parse(item)
        assert resource.Tags == {
            "Environment": "Production",
            "Owner": "team@example.com",
        }

    def test_parse_configuration_item_merges_tag_sources(self):
        """Test parsing merges tags from both the configuration blob and the top level map."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0abcd1234",
            "ARN": "arn:aws:ec2:eu-west-2:123456789012:instance/i-0abcd1234",
            "tags": {"Owner": "team@example.com"},
            "configuration": {"tags": [{"key": "Environment", "value": "Production"}]},
        }
        resource = handler.Resource.parse(item)
        assert resource.Tags == {
            "Environment": "Production",
            "Owner": "team@example.com",
        }

    def test_parse_configuration_item_null_configuration(self):
        """Test parsing when configuration is null, as sent for deleted resources."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Volume",
            "resourceId": "vol-0f750e39c7f491a40",
            "ARN": "arn:aws:ec2:eu-west-2:123456789012:volume/vol-0f750e39c7f491a40",
            "configuration": None,
            "configurationItemStatus": "ResourceDeleted",
        }
        resource = handler.Resource.parse(item)
        assert resource.ResourceId == "vol-0f750e39c7f491a40"
        assert resource.Tags == {}

    def test_parse_configuration_item_null_top_level_tags(self):
        """Test parsing when the top level tags map is null, as sent for deleted resources."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::S3::Bucket",
            "resourceId": "my-bucket",
            "ARN": None,
            "tags": None,
            "configuration": None,
        }
        resource = handler.Resource.parse(item)
        assert resource.Tags == {}

    def test_parse_configuration_item_no_tags(self):
        """Test parsing when configuration has no tags."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0abcd1234",
            "ARN": "arn:aws:ec2:eu-west-2:123456789012:instance/i-0abcd1234",
            "configuration": {},
        }
        resource = handler.Resource.parse(item)
        assert resource.Tags == {}


# ============================================================================
# Tests for evaluate function
# ============================================================================


class TestEvaluate:
    """Tests for the evaluate function."""

    def test_unmapped_type_not_applicable(self):
        """Unmapped Config type returns NOT_APPLICABLE."""
        resource = handler.Resource(
            ARN="arn:aws:foo:eu-west-2:123456789012:bar/baz",
            AccountId="123456789012",
            ResourceType="AWS::Foo::Bar",
            ResourceId="baz",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(), rules=())
        mappings = Mappings(to_config={}, to_terraform={})
        inventory = None

        compliance_type, annotation = handler.evaluate(
            resource, policy, mappings, inventory
        )

        assert compliance_type == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        assert "not taggable" in annotation.lower()

    def test_excluded_type_not_applicable_terraform_name(self):
        """Excluded resource type (Terraform name) returns NOT_APPLICABLE."""
        resource = handler.Resource(
            ARN="arn:aws:s3:::my-bucket",
            AccountId="123456789012",
            ResourceType="AWS::S3::Bucket",
            ResourceId="my-bucket",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(["aws_s3_bucket"]), rules=())
        mappings = Mappings(
            to_config={"aws_s3_bucket": "AWS::S3::Bucket"},
            to_terraform={"AWS::S3::Bucket": ("aws_s3_bucket",)},
        )
        inventory = None

        compliance_type, annotation = handler.evaluate(
            resource, policy, mappings, inventory
        )

        assert compliance_type == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        assert "excluded" in annotation.lower()

    def test_excluded_type_not_applicable_aws_name(self):
        """Excluded resource type (AWS:: name) returns NOT_APPLICABLE."""
        resource = handler.Resource(
            ARN="arn:aws:s3:::my-bucket",
            AccountId="123456789012",
            ResourceType="AWS::S3::Bucket",
            ResourceId="my-bucket",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(["AWS::S3::Bucket"]), rules=())
        mappings = Mappings(
            to_config={"aws_s3_bucket": "AWS::S3::Bucket"},
            to_terraform={"AWS::S3::Bucket": ("aws_s3_bucket",)},
        )
        inventory = None

        compliance_type, annotation = handler.evaluate(
            resource, policy, mappings, inventory
        )

        assert compliance_type == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        assert "excluded" in annotation.lower()

    def test_error_violation_non_compliant(self):
        """Error-severity violations result in NON_COMPLIANT with annotation."""
        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-123",
            AccountId="123456789012",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(), rules=())
        mappings = Mappings(
            to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
            to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
        )
        inventory = None

        outcome = Outcome(
            violations=(
                Violation("test-rule", "error", "tag Environment must be present"),
            ),
            asserted=True,
            skipped_rules=(),
        )

        with patch("handler.check_subject", return_value=outcome):
            compliance_type, annotation = handler.evaluate(
                resource, policy, mappings, inventory
            )

        assert compliance_type == handler.COMPLIANCE_TYPE_NON_COMPLIANT
        assert "test-rule" in annotation
        assert "tag Environment must be present" in annotation

    def test_warning_only_compliant(self):
        """Warning-only violations result in COMPLIANT."""
        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-123",
            AccountId="123456789012",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(), rules=())
        mappings = Mappings(
            to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
            to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
        )
        inventory = None

        outcome = Outcome(
            violations=(Violation("test-rule", "warning", "tag should be lowercase"),),
            asserted=True,
            skipped_rules=(),
        )

        with patch("handler.check_subject", return_value=outcome):
            compliance_type, annotation = handler.evaluate(
                resource, policy, mappings, inventory
            )

        assert compliance_type == handler.COMPLIANCE_TYPE_COMPLIANT
        assert annotation == handler.COMPLIANT_ANNOTATION

    def test_no_assert_reached_not_applicable(self):
        """No asserts reached results in NOT_APPLICABLE."""
        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-123",
            AccountId="123456789012",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(), rules=())
        mappings = Mappings(
            to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
            to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
        )
        inventory = None

        outcome = Outcome(
            violations=(),
            asserted=False,
            skipped_rules=(),
        )

        with patch("handler.check_subject", return_value=outcome):
            compliance_type, annotation = handler.evaluate(
                resource, policy, mappings, inventory
            )

        assert compliance_type == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        assert "no applicable rules" in annotation.lower()

    def test_account_missing_from_inventory(self):
        """Account missing from inventory: OU rule skipped, tag rule violated, one warning."""
        from policy import load_policy_text
        from store import parse_mappings

        # Real policy with OU rule and tag rule
        policy_text = """
version: 1
rules:
  - name: ou-rule
    steps:
      - filter: {organizational_path: root/workloads}
      - assert: {tag: Department, present: true}
  - name: tag-rule
    steps:
      - assert: {tag: Environment, present: true}
"""
        policy = load_policy_text(policy_text)

        # Real mappings
        mappings_text = """
version: 1
mappings:
  aws_ec2_instance: AWS::EC2::Instance
"""
        mappings = parse_mappings(mappings_text)

        # Inventory exists but doesn't contain account 999999999999
        inventory = {
            "123456789012": Account(
                account_id="123456789012",
                name="test-account",
                ou_path="root/test",
                status="ACTIVE",
                tags={},
            )
        }

        # Resource without Environment tag
        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:999999999999:instance/i-123",
            AccountId="999999999999",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={},
        )

        with patch("handler.logger") as mock_logger:
            compliance_type, annotation = handler.evaluate(
                resource, policy, mappings, inventory
            )

        # NON_COMPLIANT because tag-rule failed
        assert compliance_type == handler.COMPLIANCE_TYPE_NON_COMPLIANT
        # Annotation should mention tag-rule but not ou-rule
        assert "tag-rule" in annotation
        assert "Environment" in annotation
        assert "ou-rule" not in annotation

        # Exactly one warning about account not found
        warning_calls = [
            call
            for call in mock_logger.warning.call_args_list
            if "account not found in inventory" in call[0][0].lower()
        ]
        assert len(warning_calls) == 1

    def test_annotation_truncated(self):
        """Many violations result in annotation truncated to 256 chars ending in ..."""
        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-123",
            AccountId="123456789012",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={},
        )
        policy = Policy(exclude_resource_types=frozenset(), rules=())
        mappings = Mappings(
            to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
            to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
        )
        inventory = None

        # Create 20 violations to ensure truncation
        violations = tuple(
            Violation(f"rule-{i}", "error", f"tag Tag{i} must be present")
            for i in range(20)
        )
        outcome = Outcome(
            violations=violations,
            asserted=True,
            skipped_rules=(),
        )

        with patch("handler.check_subject", return_value=outcome):
            compliance_type, annotation = handler.evaluate(
                resource, policy, mappings, inventory
            )

        assert compliance_type == handler.COMPLIANCE_TYPE_NON_COMPLIANT
        assert len(annotation) == 256
        assert annotation.endswith("...")

    def test_skipped_rules_deduplication(self):
        """Two evaluate calls with distinct Policy objects but same skipped rules → one log."""
        from policy import load_policy_text
        from store import parse_mappings

        policy_text = """
version: 1
rules:
  - name: ou-rule
    steps:
      - filter: {organizational_path: root/workloads}
      - assert: {tag: Department, present: true}
"""
        mappings_text = """
version: 1
mappings:
  aws_ec2_instance: AWS::EC2::Instance
"""

        # Parse twice to get distinct Policy objects
        policy1 = load_policy_text(policy_text)
        policy2 = load_policy_text(policy_text)
        assert id(policy1) != id(policy2)  # Distinct objects

        mappings = parse_mappings(mappings_text)
        inventory = None  # No inventory → rules with OU filters are skipped

        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-123",
            AccountId="123456789012",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={},
        )

        # Clear the module-level set before test
        handler._logged_skipped_rules.clear()

        with patch("handler.logger") as mock_logger:
            # First call
            handler.evaluate(resource, policy1, mappings, inventory)
            # Second call with distinct policy object
            handler.evaluate(resource, policy2, mappings, inventory)

        # Should have exactly one info log about skipped rules
        info_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "rules skipped" in call[0][0].lower()
        ]
        assert len(info_calls) == 1

    def test_no_skipped_rules_no_log(self):
        """Policy with no OU/account_tag rules → no 'rules skipped' log."""
        from policy import load_policy_text
        from store import parse_mappings

        policy_text = """
version: 1
rules:
  - name: tag-rule
    steps:
      - assert: {tag: Environment, present: true}
"""
        policy = load_policy_text(policy_text)

        mappings_text = """
version: 1
mappings:
  aws_ec2_instance: AWS::EC2::Instance
"""
        mappings = parse_mappings(mappings_text)
        inventory = None  # No inventory

        resource = handler.Resource(
            ARN="arn:aws:ec2:eu-west-2:123456789012:instance/i-123",
            AccountId="123456789012",
            ResourceType="AWS::EC2::Instance",
            ResourceId="i-123",
            Tags={"Environment": "Production"},
        )

        handler._logged_skipped_rules.clear()

        with patch("handler.logger") as mock_logger:
            handler.evaluate(resource, policy, mappings, inventory)

        # Should have no info log about skipped rules
        info_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "rules skipped" in call[0][0].lower()
        ]
        assert len(info_calls) == 0

    def test_subject_wiring(self):
        """terraform_types and tags properly wired to Subject."""
        from policy import load_policy_text
        from store import parse_mappings

        policy_text = """
version: 1
rules:
  - name: require-owner
    steps:
      - filter: {type: aws_s3_bucket}
      - assert: {tag: Owner, present: true}
"""
        policy = load_policy_text(policy_text)

        mappings_text = """
version: 1
mappings:
  aws_s3_bucket: AWS::S3::Bucket
"""
        mappings = parse_mappings(mappings_text)
        inventory = None

        # Resource with Owner tag → COMPLIANT
        resource_with_owner = handler.Resource(
            ARN="arn:aws:s3:::my-bucket",
            AccountId="123456789012",
            ResourceType="AWS::S3::Bucket",
            ResourceId="my-bucket",
            Tags={"Owner": "team@example.com"},
        )

        compliance_type, _ = handler.evaluate(
            resource_with_owner, policy, mappings, inventory
        )
        assert compliance_type == handler.COMPLIANCE_TYPE_COMPLIANT

        # Resource without Owner tag → NON_COMPLIANT
        resource_without_owner = handler.Resource(
            ARN="arn:aws:s3:::my-bucket",
            AccountId="123456789012",
            ResourceType="AWS::S3::Bucket",
            ResourceId="my-bucket",
            Tags={},
        )

        compliance_type, annotation = handler.evaluate(
            resource_without_owner, policy, mappings, inventory
        )
        assert compliance_type == handler.COMPLIANCE_TYPE_NON_COMPLIANT
        assert "Owner" in annotation


# ============================================================================
# Tests for filter_on_resources
# ============================================================================


class TestFilterOnResources:
    """Tests for filter_on_resources function."""

    def test_filter_on_resources_skips_aws_managed_role(self):
        """AWS managed IAM roles should be filtered out."""
        resource = handler.Resource(
            AccountId="123456789012",
            ARN="arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
            ResourceType="AWS::IAM::Role",
            ResourceId="AWSServiceRoleForSupport",
            Tags={},
        )

        assert handler.filter_on_resources(resource) is True

    def test_filter_on_resources_allows_regular_role(self):
        """Regular IAM roles should not be filtered out."""
        resource = handler.Resource(
            AccountId="123456789012",
            ARN="arn:aws:iam::123456789012:role/application-role",
            ResourceType="AWS::IAM::Role",
            ResourceId="application-role",
            Tags={},
        )

        assert handler.filter_on_resources(resource) is False


# ============================================================================
# Tests for validate_configuration_event
# ============================================================================


class TestValidateConfigurationEvent:
    """Tests for validate_configuration_event function."""

    def test_validate_configuration_event_valid(self, sample_config_event):
        """Test validation passes for valid event."""
        # Should not raise
        handler.validate_configuration_event(sample_config_event)

    def test_validate_configuration_event_missing_field(self):
        """Test validation fails when required field is missing."""
        event = {"invokingEvent": "{}"}  # Missing other required fields
        with pytest.raises(ValueError, match="missing required field"):
            handler.validate_configuration_event(event)


# ============================================================================
# Tests for validate_environment
# ============================================================================


class TestValidateEnvironment:
    """Tests for validate_environment function."""

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "my-policy-bucket",
        },
    )
    def test_validate_environment_valid(self):
        """Test validation passes when all required env vars are set."""
        # Should not raise
        handler.validate_environment()

    @patch.dict(os.environ, {}, clear=True)
    def test_validate_environment_missing_var(self):
        """Test validation fails when required env var is missing."""
        with pytest.raises(ValueError, match="required but not set"):
            handler.validate_environment()


# ============================================================================
# Tests for lambda_handler
# ============================================================================


_WARNING_POLICY = """
version: 1
exclude_resource_types: [aws_unknown_excluded, aws_s3_bucket, AWS::Not::Mapped]
rules:
  - name: parent
    steps:
      - filter: {type: [aws_instance, aws_missing_parent, AWS::EC2::Volume]}
      - assert: {tag: Owner, present: true}
    rules:
      - name: child
        steps:
          - filter: {type: {in: [aws_missing_child]}}
          - filter: {type: {starts_with: aws_s3_}}
          - filter: {type: {is_snake: true}}
          - assert: {tag: Env, present: true}
  - name: by-address
    steps:
      - filter: {address: {matches: "^module\\\\.app"}}
      - assert: {tag: Env, present: true}
"""

_WARNING_MAPPINGS = """
version: 1
mappings:
  aws_instance: AWS::EC2::Instance
  aws_s3_bucket: AWS::S3::Bucket
"""


class TestPolicyWarnings:
    """Load-time warnings about unmapped Terraform types and address conditions."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        handler._logged_policy_warnings.clear()

    @staticmethod
    def _load(policy_text=_WARNING_POLICY, mappings_text=_WARNING_MAPPINGS):
        from policy import load_policy_text
        from store import parse_mappings

        return load_policy_text(policy_text), parse_mappings(mappings_text)

    @staticmethod
    def _warnings(mock_logger):
        return {
            call[0][0]: call[1]["extra"] for call in mock_logger.warning.call_args_list
        }

    def test_warns_unmapped_types_and_address_once(self):
        """Unmapped type operands/exclusions and address rules are each warned once."""
        policy, mappings = self._load()

        with patch("handler.logger") as mock_logger:
            handler.log_policy_warnings(policy, mappings)
            handler.log_policy_warnings(*self._load())

        assert mock_logger.warning.call_count == 2
        warnings = self._warnings(mock_logger)
        unmapped = warnings["Policy references Terraform types missing from mappings"]
        assert unmapped["unmapped_types"] == [
            "aws_missing_child",
            "aws_missing_parent",
            "aws_unknown_excluded",
        ]
        address = warnings["Policy has address conditions, which never match in Config"]
        assert address["rules"] == ["by-address"]

    def test_warns_again_when_reported_names_change(self):
        """A policy change that alters the reported names logs again."""
        policy, mappings = self._load()
        changed, _ = self._load(_WARNING_POLICY.replace("aws_missing_child", "aws_x"))

        with patch("handler.logger") as mock_logger:
            handler.log_policy_warnings(policy, mappings)
            handler.log_policy_warnings(changed, mappings)

        unmapped = [
            call[1]["extra"]["unmapped_types"]
            for call in mock_logger.warning.call_args_list
            if "missing from mappings" in call[0][0]
        ]
        assert len(unmapped) == 2
        assert "aws_x" in unmapped[1]

    def test_no_warnings_for_clean_policy(self):
        """A policy whose Terraform types are all mapped logs nothing."""
        clean = """
version: 1
exclude_resource_types: [aws_s3_bucket, AWS::Not::Mapped]
rules:
  - name: r
    steps:
      - filter: {type: aws_instance}
      - assert: {tag: Env, present: true}
"""
        policy, mappings = self._load(clean)

        with patch("handler.logger") as mock_logger:
            handler.log_policy_warnings(policy, mappings)

        mock_logger.warning.assert_not_called()

    @patch.dict(os.environ, {"POLICY_BUCKET": "test-bucket"})
    @patch("handler.store")
    @patch("handler.config_client")
    def test_handler_logs_warnings_after_load(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """lambda_handler warns once across events for the same policy."""
        policy, mappings = self._load()
        mock_store.load_policy.return_value = policy
        mock_store.load_mappings.return_value = mappings
        mock_store.load_inventory.return_value = None

        with patch("handler.logger") as mock_logger:
            handler.lambda_handler(sample_config_event, None)
            handler.lambda_handler(sample_config_event, None)

        messages = [call[0][0] for call in mock_logger.warning.call_args_list]
        assert (
            messages.count("Policy references Terraform types missing from mappings")
            == 1
        )
        assert (
            messages.count("Policy has address conditions, which never match in Config")
            == 1
        )


class TestLambdaHandler:
    """Tests for the main lambda_handler function."""

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "my-policy-bucket",
        },
    )
    @patch("handler.store")
    @patch("handler.config_client")
    def test_invalid_policy_puts_nothing(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """Invalid policy raises and put_evaluations is not called."""
        mock_store.load_policy.side_effect = PolicyError("invalid policy")

        with pytest.raises(PolicyError):
            handler.lambda_handler(sample_config_event, None)

        mock_config_client.put_evaluations.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "test-bucket",
            "POLICY_KEY": "custom-policy.yaml",
            "MAPPINGS_KEY": "custom-mappings.yaml",
            "ACCOUNTS_KEY": "custom-accounts.yaml",
        },
    )
    @patch("handler.store")
    @patch("handler.config_client")
    def test_handler_reads_env(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """Handler reads environment variables and passes them to store."""
        mock_store.load_policy.return_value = Policy(
            exclude_resource_types=frozenset(), rules=()
        )
        mock_store.load_mappings.return_value = Mappings(
            to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
            to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
        )
        mock_store.load_inventory.return_value = None
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(sample_config_event, None)

        # Verify store functions were called with correct parameters
        mock_store.load_policy.assert_called_once_with(
            "test-bucket", "custom-policy.yaml"
        )
        mock_store.load_mappings.assert_called_once_with(
            "test-bucket", "custom-mappings.yaml"
        )
        mock_store.load_inventory.assert_called_once_with(
            "test-bucket", "custom-accounts.yaml"
        )

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "test-bucket",
            # ACCOUNTS_KEY not set
        },
    )
    @patch("handler.store")
    @patch("handler.config_client")
    def test_handler_accounts_key_unset(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """Handler passes None to load_inventory when ACCOUNTS_KEY is unset."""
        mock_store.load_policy.return_value = Policy(
            exclude_resource_types=frozenset(), rules=()
        )
        mock_store.load_mappings.return_value = Mappings(
            to_config={"aws_ec2_instance": "AWS::EC2::Instance"},
            to_terraform={"AWS::EC2::Instance": ("aws_ec2_instance",)},
        )
        mock_store.load_inventory.return_value = None
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(sample_config_event, None)

        # Verify load_inventory was called with None key
        mock_store.load_inventory.assert_called_once_with("test-bucket", None)

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "test-bucket",
        },
    )
    @patch("handler.store")
    @patch("handler.config_client")
    def test_lambda_handler_deleted_resource(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """Test lambda handler with a deleted resource."""
        # Modify event to indicate resource was deleted
        event = sample_config_event.copy()
        invoking_event = json.loads(event["invokingEvent"])
        invoking_event["configurationItem"][
            "configurationItemStatus"
        ] = "ResourceDeleted"
        invoking_event["configurationItem"]["configuration"] = None
        event["invokingEvent"] = json.dumps(invoking_event)

        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(event, None)

        # Verify put_evaluations was called with NOT_APPLICABLE status
        call_args = mock_config_client.put_evaluations.call_args[1]
        evaluation = call_args["Evaluations"][0]
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        assert "deleted" in evaluation["Annotation"].lower()

        # Store functions should not be called for deleted resources
        mock_store.load_policy.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "test-bucket",
        },
    )
    @patch("handler.store")
    @patch("handler.config_client")
    def test_lambda_handler_filtered_resource(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """Test lambda handler skips AWS managed IAM roles."""
        event = sample_config_event.copy()
        invoking_event = json.loads(event["invokingEvent"])
        invoking_event["configurationItem"]["resourceType"] = "AWS::IAM::Role"
        invoking_event["configurationItem"]["resourceId"] = "AWSServiceRoleForSupport"
        invoking_event["configurationItem"][
            "ARN"
        ] = "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"
        event["invokingEvent"] = json.dumps(invoking_event)

        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(event, None)

        call_args = mock_config_client.put_evaluations.call_args[1]
        evaluation = call_args["Evaluations"][0]
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_NOT_APPLICABLE

        # Store functions should not be called for filtered resources
        mock_store.load_policy.assert_not_called()

    def test_lambda_handler_missing_required_field(self):
        """Test lambda handler fails when event is missing required field."""
        event = {"invokingEvent": "{}"}  # Missing other fields
        with pytest.raises(ValueError, match="missing required field"):
            handler.lambda_handler(event, None)

    @patch.dict(os.environ, {}, clear=True)
    def test_lambda_handler_missing_environment_variable(self, sample_config_event):
        """Test lambda handler fails when required env var is missing."""
        with pytest.raises(ValueError, match="required but not set"):
            handler.lambda_handler(sample_config_event, None)

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "test-bucket",
        },
    )
    @patch("handler.config_client")
    def test_lambda_handler_deleted_resource_null_arn(
        self, mock_config_client, sample_config_event
    ):
        """Test lambda handler with deleted resource (null ARN, ResourceDeleted status)."""
        # AWS Config sends null ARN and configuration once resource is gone
        event = sample_config_event.copy()
        invoking_event = json.loads(event["invokingEvent"])
        invoking_event["configurationItem"][
            "configurationItemStatus"
        ] = "ResourceDeleted"
        invoking_event["configurationItem"]["ARN"] = None
        invoking_event["configurationItem"]["configuration"] = None
        event["invokingEvent"] = json.dumps(invoking_event)

        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(event, None)

        # Verify put_evaluations called once with NOT_APPLICABLE
        mock_config_client.put_evaluations.assert_called_once()
        call_args = mock_config_client.put_evaluations.call_args[1]
        evaluation = call_args["Evaluations"][0]
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_NOT_APPLICABLE

    @patch.dict(
        os.environ,
        {
            "POLICY_BUCKET": "test-bucket",
            "POLICY_KEY": "policy.yaml",
            "MAPPINGS_KEY": "mappings.yaml",
        },
    )
    @patch("handler.store")
    @patch("handler.config_client")
    def test_lambda_handler_end_to_end(
        self, mock_config_client, mock_store, sample_config_event
    ):
        """End-to-end test with real Policy/Mappings, verifying exact put_evaluations call."""
        from policy import load_policy_text
        from store import parse_mappings

        # Real policy requiring Environment tag
        policy_text = """
version: 1
rules:
  - name: require-environment
    steps:
      - assert: {tag: Environment, present: true}
"""
        policy = load_policy_text(policy_text)

        # Real mappings
        mappings_text = """
version: 1
mappings:
  aws_ec2_instance: AWS::EC2::Instance
"""
        mappings = parse_mappings(mappings_text)

        # Mock store to return real objects
        mock_store.load_policy.return_value = policy
        mock_store.load_mappings.return_value = mappings
        mock_store.load_inventory.return_value = None
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(sample_config_event, None)

        # Verify exact put_evaluations call
        mock_config_client.put_evaluations.assert_called_once()
        call_args = mock_config_client.put_evaluations.call_args[1]

        # Check Evaluations list
        evaluations = call_args["Evaluations"]
        assert len(evaluations) == 1
        evaluation = evaluations[0]

        # Verify exact fields
        assert evaluation["ComplianceResourceType"] == "AWS::EC2::Instance"
        assert evaluation["ComplianceResourceId"] == "i-0abcd1234efgh5678"
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_COMPLIANT
        assert "compliant" in evaluation["Annotation"].lower()
        assert "OrderingTimestamp" in evaluation

        # Verify ResultToken
        assert call_args["ResultToken"] == "test-result-token-12345"
