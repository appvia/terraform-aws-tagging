"""
Unit tests for the AWS Config tagging compliance Lambda handler.

Tests cover:
- TypedDict classes and their methods
- Parsing and validation functions
- Rule matching logic
- Compliance evaluation
- Lambda handler integration
"""

import json
import os
from unittest.mock import patch

import pytest

import handler

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_resource():
    """A sample Resource dict for testing."""
    return handler.Resource(
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
def sample_rule_required():
    """A sample Rule that requires a specific tag with allowed values."""
    return handler.Rule(
        AccountIds=["*"],
        Enabled=True,
        Required=True,
        ResourceType="AWS::EC2::*",
        Tag="Environment",
        ValuePattern="",
        Values=["Production", "Staging", "Development"],
    )


@pytest.fixture
def sample_rule_optional():
    """A sample Rule that checks a tag only if present (not required)."""
    return handler.Rule(
        AccountIds=["123456789012"],
        Enabled=True,
        Required=False,
        ResourceType="AWS::EC2::Instance",
        Tag="DataClassification",
        RuleId="optional-data-classification",
        ValuePattern="",
        Values=["Public", "Private", "Confidential"],
    )


@pytest.fixture
def sample_rule_pattern():
    """A sample Rule that validates tag value against a regex pattern."""
    return handler.Rule(
        AccountIds=["*"],
        Enabled=True,
        Required=True,
        ResourceType="AWS::EC2::*",
        RuleId="ec2-owner-email",
        Tag="Owner",
        ValuePattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        Values=[],
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
                    "configuration": {
                        "instanceId": "i-0abcd1234efgh5678",
                        "instanceType": "t3.medium",
                        "tags": {
                            "Name": "my-ec2-instance",
                            "Environment": "Production",
                        },
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
def sample_dynamodb_item():
    """A sample DynamoDB item representing a tagging rule."""
    return {
        "ResourceType": {"S": "AWS::EC2::*"},
        "Tag": {"S": "Environment"},
        "Enabled": {"B": True},
        "Required": {"B": True},
        "RuleId": {"S": "optional-data-classification"},
        "ValuePattern": {"S": ""},
        "Values": {"S": '["Production", "Staging", "Development"]'},
        "AccountIds": {"S": '["*"]'},
    }


# ============================================================================
# Tests for Resource TypedDict methods
# ============================================================================


class TestResource:
    """Tests for the Resource TypedDict class."""

    def test_contains_tag_present(self, sample_resource):
        """Test contains() returns True when tag is present."""
        assert sample_resource.contains("Environment") is True
        assert sample_resource.contains("CostCenter") is True

    def test_contains_tag_absent(self, sample_resource):
        """Test contains() returns False when tag is absent."""
        assert sample_resource.contains("NonExistentTag") is False

    def test_is_value_matching(self, sample_resource):
        """Test is_value() returns True when tag value is in permitted list."""
        assert (
            sample_resource.is_value("Environment", ["Production", "Staging"]) is True
        )

    def test_is_value_not_matching(self, sample_resource):
        """Test is_value() returns False when tag value is not in permitted list."""
        assert (
            sample_resource.is_value("Environment", ["Staging", "Development"]) is False
        )

    def test_is_value_tag_absent(self, sample_resource):
        """Test is_value() returns False when tag is absent."""
        assert sample_resource.is_value("NonExistent", ["Value"]) is False

    def test_is_value_pattern_matching(self, sample_resource):
        """Test is_value_pattern() returns True when tag value matches regex."""
        assert (
            sample_resource.is_value_pattern(
                "Owner", r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            )
            is True
        )

    def test_is_value_pattern_not_matching(self, sample_resource):
        """Test is_value_pattern() returns False when tag value doesn't match regex."""
        assert sample_resource.is_value_pattern("Owner", r"^\d+$") is False

    def test_is_value_pattern_tag_absent(self, sample_resource):
        """Test is_value_pattern() returns False when tag is absent."""
        assert sample_resource.is_value_pattern("NonExistent", r".*") is False


# ============================================================================
# Tests for Rule TypedDict methods
# ============================================================================


class TestRule:
    """Tests for the Rule TypedDict class."""

    def test_has_values_true(self, sample_rule_required):
        """Test has_values() returns True when Values list is non-empty."""
        assert sample_rule_required.has_values() is True

    def test_has_values_false(self, sample_rule_pattern):
        """Test has_values() returns False when Values list is empty."""
        assert sample_rule_pattern.has_values() is False

    def test_has_value_pattern_true(self, sample_rule_pattern):
        """Test has_value_pattern() returns True when ValuePattern is non-empty."""
        assert sample_rule_pattern.has_value_pattern() is True

    def test_has_value_pattern_false(self, sample_rule_required):
        """Test has_value_pattern() returns False when ValuePattern is empty."""
        assert sample_rule_required.has_value_pattern() is False


# ============================================================================
# Tests for Evaluations TypedDict methods
# ============================================================================


class TestEvaluations:
    """Tests for the Evaluations TypedDict class."""

    def test_is_compliant_all_compliant(self):
        """Test is_compliant() returns True when all evaluations are compliant."""
        evaluations = handler.Evaluations(
            Evaluations=[
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_COMPLIANT),
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_COMPLIANT),
            ]
        )
        assert evaluations.is_compliant() is True

    def test_is_compliant_some_non_compliant(self):
        """Test is_compliant() returns False when any evaluation is non-compliant."""
        evaluations = handler.Evaluations(
            Evaluations=[
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_COMPLIANT),
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_NON_COMPLIANT),
            ]
        )
        assert evaluations.is_compliant() is False

    def test_is_compliant_not_applicable(self):
        """Test is_compliant() returns False for NOT_APPLICABLE evaluations."""
        evaluations = handler.Evaluations(
            Evaluations=[
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_NOT_APPLICABLE),
            ]
        )
        assert evaluations.is_compliant() is False

    def test_is_non_applicable_all_not_applicable(self):
        """Test is_non_applicable() returns True when all are NOT_APPLICABLE."""
        evaluations = handler.Evaluations(
            Evaluations=[
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_NOT_APPLICABLE),
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_NOT_APPLICABLE),
            ]
        )
        assert evaluations.is_non_applicable() is True

    def test_is_non_applicable_mixed(self):
        """Test is_non_applicable() returns False when not all are NOT_APPLICABLE."""
        evaluations = handler.Evaluations(
            Evaluations=[
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_NOT_APPLICABLE),
                handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_COMPLIANT),
            ]
        )
        assert evaluations.is_non_applicable() is False

    def test_add_evaluation(self):
        """Test add() adds an evaluation to the list."""
        evaluations = handler.Evaluations(Evaluations=[])
        evaluation = handler.Evaluation(Compliant=handler.COMPLIANCE_TYPE_COMPLIANT)
        evaluations.add(evaluation)
        assert len(evaluations.Evaluations) == 1
        assert evaluations.Evaluations[0] == evaluation

    def test_non_applicable_method(self):
        """Test non_applicable() adds a NOT_APPLICABLE evaluation."""
        evaluations = handler.Evaluations(Evaluations=[])
        evaluations.non_applicable("Resource not applicable")
        assert len(evaluations.Evaluations) == 1
        assert (
            evaluations.Evaluations[0].Compliant
            == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        )
        assert evaluations.Evaluations[0].Annotation == "Resource not applicable"

    def test_non_compliant_method(self):
        """Test non_compliant() adds a NON_COMPLIANT evaluation."""
        evaluations = handler.Evaluations(Evaluations=[])
        evaluations.non_compliant(
            annotation="Tag value not permitted",
            tag="Environment",
            value="Invalid",
        )
        assert len(evaluations.Evaluations) == 1
        assert (
            evaluations.Evaluations[0].Compliant
            == handler.COMPLIANCE_TYPE_NON_COMPLIANT
        )
        assert evaluations.Evaluations[0].TagKey == "Environment"
        assert evaluations.Evaluations[0].TagValue == "Invalid"
        assert evaluations.Evaluations[0].Annotation == "Tag value not permitted"


# ============================================================================
# Tests for parsing functions
# ============================================================================


class TestParseConfigurationItem:
    """Tests for parse_configuration_item function."""

    def test_parse_valid_configuration_item(self):
        """Test parsing a valid configuration item."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0abcd1234",
            "configuration": {
                "instanceId": "i-0abcd1234",
                "tags": {"Environment": "Production", "Name": "test-instance"},
            },
        }
        resource = handler.parse_configuration_item(item)
        assert resource.AccountId == "123456789012"
        assert resource.ResourceType == "AWS::EC2::Instance"
        assert resource.ResourceId == "i-0abcd1234"
        assert resource.Tags["Environment"] == "Production"

    def test_parse_configuration_item_missing_field(self):
        """Test parsing fails when required field is missing."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            # Missing resourceId
            "configuration": {"tags": {}},
        }
        with pytest.raises(ValueError, match="missing required field"):
            handler.parse_configuration_item(item)

    def test_parse_configuration_item_no_tags(self):
        """Test parsing when configuration has no tags."""
        item = {
            "awsAccountId": "123456789012",
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0abcd1234",
            "configuration": {},
        }
        resource = handler.parse_configuration_item(item)
        assert resource.Tags == {}


class TestParseRule:
    """Tests for parse_rule function."""

    def test_parse_complete_rule(self, sample_dynamodb_item):
        """Test parsing a complete DynamoDB rule item."""
        rule = handler.parse_rule(sample_dynamodb_item)
        assert rule.AccountIds == ["*"]
        assert rule.Enabled is True
        assert rule.Required is True
        assert rule.ResourceType == "AWS::EC2::*"
        assert rule.Tag == "Environment"
        assert rule.RuleId == "optional-data-classification"
        assert rule.ValuePattern == ""
        assert rule.Values == ["Production", "Staging", "Development"]

    def test_parse_rule_with_defaults(self):
        """Test parsing a rule with missing optional fields uses defaults."""
        item = {
            "ResourceType": {"S": "AWS::S3::Bucket"},
            "Tag": {"S": "DataClassification"},
        }
        rule = handler.parse_rule(item)
        assert rule.AccountIds == ["*"]
        assert rule.Enabled is True
        assert rule.Required is True
        assert rule.RuleId == ""
        assert rule.ValuePattern == ""
        assert rule.Values == []


# ============================================================================
# Tests for rule matching
# ============================================================================


class TestFindMatchingRules:
    """Tests for find_matching_rules function."""

    def test_find_matching_rules_exact_match(
        self, sample_resource, sample_rule_required
    ):
        """Test finding rules that exactly match resource type."""
        rules = [sample_rule_required]
        matching = handler.find_matching_rules(rules, sample_resource)
        assert len(matching) == 1
        assert matching[0].Tag == "Environment"

    def test_find_matching_rules_wildcard_resource_type(self, sample_resource):
        """Test finding rules with wildcard resource type."""
        rule = handler.Rule(
            AccountIds=["*"],
            Enabled=True,
            Required=True,
            ResourceType="*",
            Tag="Owner",
            ValuePattern="",
            Values=[],
        )
        matching = handler.find_matching_rules([rule], sample_resource)
        assert len(matching) == 1

    def test_find_matching_rules_disabled_rule_excluded(
        self, sample_resource, sample_rule_required
    ):
        """Test disabled rules are excluded from matches."""
        sample_rule_required.Enabled = False
        matching = handler.find_matching_rules([sample_rule_required], sample_resource)
        assert len(matching) == 0

    def test_find_matching_rules_account_mismatch(self, sample_resource):
        """Test rules with non-matching account IDs are excluded."""
        rule = handler.Rule(
            AccountIds=["999999999999"],
            Enabled=True,
            Required=True,
            ResourceType="AWS::EC2::Instance",
            Tag="Environment",
            ValuePattern="",
            Values=[],
        )
        matching = handler.find_matching_rules([rule], sample_resource)
        assert len(matching) == 0

    def test_find_matching_rules_resource_type_mismatch(self, sample_resource):
        """Test rules with non-matching resource types are excluded."""
        rule = handler.Rule(
            AccountIds=["*"],
            Enabled=True,
            Required=True,
            ResourceType="AWS::S3::Bucket",
            Tag="Environment",
            ValuePattern="",
            Values=[],
        )
        matching = handler.find_matching_rules([rule], sample_resource)
        assert len(matching) == 0

    def test_find_matching_rules_multiple_matches(self, sample_resource):
        """Test finding multiple matching rules."""
        rules = [
            handler.Rule(
                AccountIds=["*"],
                Enabled=True,
                Required=True,
                ResourceType="AWS::EC2::*",
                Tag="Environment",
                ValuePattern="",
                Values=["Production"],
            ),
            handler.Rule(
                AccountIds=["*"],
                Enabled=True,
                Required=True,
                ResourceType="AWS::EC2::Instance",
                Tag="CostCenter",
                ValuePattern="",
                Values=[],
            ),
        ]
        matching = handler.find_matching_rules(rules, sample_resource)
        assert len(matching) == 2


# ============================================================================
# Tests for compliance validation
# ============================================================================


class TestValidateCompliance:
    """Tests for validate_compliance function."""

    def test_validate_compliance_all_rules_satisfied(
        self, sample_resource, sample_rule_required
    ):
        """Test resource compliant when all rules are satisfied."""
        rules = [sample_rule_required]
        evaluations = handler.validate_compliance(rules, sample_resource)
        assert evaluations.is_compliant() is True

    def test_validate_compliance_missing_required_tag(self, sample_resource):
        """Test resource non-compliant when required tag is missing."""
        rule = handler.Rule(
            AccountIds=["*"],
            Enabled=True,
            Required=True,
            ResourceType="AWS::EC2::*",
            Tag="MissingTag",
            ValuePattern="",
            Values=[],
        )
        evaluations = handler.validate_compliance([rule], sample_resource)
        assert evaluations.is_compliant() is False
        assert len(evaluations.Evaluations) == 1
        assert "missing" in evaluations.Evaluations[0].Annotation.lower()

    def test_validate_compliance_tag_value_not_in_permitted_list(
        self, sample_resource, sample_rule_required
    ):
        """Test resource non-compliant when tag value not in permitted list."""
        sample_rule_required.Values = ["Staging", "Development"]
        evaluations = handler.validate_compliance(
            [sample_rule_required], sample_resource
        )
        assert evaluations.is_compliant() is False
        assert len(evaluations.Evaluations) == 1
        assert "permitted values" in evaluations.Evaluations[0].Annotation

    def test_validate_compliance_pattern_match(
        self, sample_resource, sample_rule_pattern
    ):
        """Test resource compliant when tag value matches regex pattern."""
        evaluations = handler.validate_compliance(
            [sample_rule_pattern], sample_resource
        )
        assert evaluations.is_compliant() is True

    def test_validate_compliance_pattern_mismatch(self, sample_resource):
        """Test resource non-compliant when tag value doesn't match pattern."""
        rule = handler.Rule(
            AccountIds=["*"],
            Enabled=True,
            Required=True,
            ResourceType="AWS::EC2::*",
            Tag="CostCenter",
            ValuePattern=r"^\d{6}$",  # Requires exactly 6 digits
            Values=[],
        )
        evaluations = handler.validate_compliance([rule], sample_resource)
        assert evaluations.is_compliant() is False
        assert "pattern" in evaluations.Evaluations[0].Annotation

    def test_validate_compliance_optional_tag_missing(
        self, sample_resource, sample_rule_optional
    ):
        """Test optional tag doesn't cause non-compliance when missing."""
        sample_rule_optional.Tag = "OptionalTag"
        evaluations = handler.validate_compliance(
            [sample_rule_optional], sample_resource
        )
        # Should be compliant since the optional tag is not present
        assert evaluations.is_compliant() is True


# ============================================================================
# Tests for validation functions
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


class TestValidateEnvironment:
    """Tests for validate_environment function."""

    @patch.dict(
        os.environ,
        {
            "ACCOUNT_ID": "123456789012",
            "TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/tagging",
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
# Tests for get_rules function
# ============================================================================


class TestGetRules:
    """Tests for get_rules function."""

    @patch("handler.table_client")
    def test_get_rules_success(self, mock_client, sample_dynamodb_item):
        """Test retrieving rules from DynamoDB."""
        mock_client.scan.return_value = {"Items": [sample_dynamodb_item]}

        table_arn = "arn:aws:dynamodb:us-east-1:123456789012:table/tagging-compliance"
        rules = handler.get_rules(table_arn)

        assert len(rules) == 1
        assert rules[0].ResourceType == "AWS::EC2::*"
        assert rules[0].Tag == "Environment"
        mock_client.scan.assert_called_once_with(TableName="tagging-compliance")

    @patch("handler.table_client")
    def test_get_rules_empty_table(self, mock_client):
        """Test retrieving rules from empty DynamoDB table."""
        mock_client.scan.return_value = {"Items": []}

        table_arn = "arn:aws:dynamodb:us-east-1:123456789012:table/tagging-compliance"
        rules = handler.get_rules(table_arn)

        assert len(rules) == 0


# ============================================================================
# Tests for lambda_handler
# ============================================================================


class TestLambdaHandler:
    """Tests for the main lambda_handler function."""

    @patch.dict(
        os.environ,
        {
            "ACCOUNT_ID": "123456789012",
            "TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/tagging-compliance",
        },
    )
    @patch("handler.config_client")
    @patch("handler.table_client")
    def test_lambda_handler_compliant_resource(
        self,
        mock_table_client,
        mock_config_client,
        sample_config_event,
        sample_dynamodb_item,
    ):
        """Test lambda handler with a compliant resource."""
        mock_table_client.scan.return_value = {"Items": [sample_dynamodb_item]}
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(sample_config_event, None)

        # Verify put_evaluations was called with compliant status
        mock_config_client.put_evaluations.assert_called_once()
        call_args = mock_config_client.put_evaluations.call_args[1]
        assert len(call_args["Evaluations"]) == 1
        evaluation = call_args["Evaluations"][0]
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_COMPLIANT
        assert call_args["ResultToken"] == "test-result-token-12345"

    @patch.dict(
        os.environ,
        {
            "ACCOUNT_ID": "123456789012",
            "TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/tagging-compliance",
        },
    )
    @patch("handler.config_client")
    @patch("handler.table_client")
    def test_lambda_handler_non_compliant_resource(
        self, mock_table_client, mock_config_client, sample_config_event
    ):
        """Test lambda handler with a non-compliant resource."""
        # Rule requires "Development" value which the resource doesn't have
        rule_item = {
            "ResourceType": {"S": "AWS::EC2::*"},
            "Tag": {"S": "Environment"},
            "Enabled": {"B": True},
            "Required": {"B": True},
            "ValuePattern": {"S": ""},
            "Values": {"S": '["Development"]'},  # Resource has "Production"
            "AccountIds": {"S": '["*"]'},
        }
        mock_table_client.scan.return_value = {"Items": [rule_item]}
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(sample_config_event, None)

        # Verify put_evaluations was called with non-compliant status
        call_args = mock_config_client.put_evaluations.call_args[1]
        evaluation = call_args["Evaluations"][0]
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_NON_COMPLIANT

    @patch.dict(
        os.environ,
        {
            "ACCOUNT_ID": "123456789012",
            "TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/tagging-compliance",
        },
    )
    @patch("handler.config_client")
    @patch("handler.table_client")
    def test_lambda_handler_deleted_resource(
        self, mock_table_client, mock_config_client, sample_config_event
    ):
        """Test lambda handler with a deleted resource."""
        # Modify event to indicate resource was deleted
        event = sample_config_event.copy()
        invoking_event = json.loads(event["invokingEvent"])
        invoking_event["configurationItem"][
            "configurationItemStatus"
        ] = "ResourceDeleted"
        event["invokingEvent"] = json.dumps(invoking_event)

        mock_table_client.scan.return_value = {"Items": []}
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(event, None)

        # Verify put_evaluations was called with NOT_APPLICABLE status
        call_args = mock_config_client.put_evaluations.call_args[1]
        evaluation = call_args["Evaluations"][0]
        assert evaluation["ComplianceType"] == handler.COMPLIANCE_TYPE_NOT_APPLICABLE

    @patch.dict(
        os.environ,
        {
            "ACCOUNT_ID": "123456789012",
            "TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/tagging-compliance",
        },
    )
    @patch("handler.config_client")
    @patch("handler.table_client")
    def test_lambda_handler_no_matching_rules(
        self, mock_table_client, mock_config_client, sample_config_event
    ):
        """Test lambda handler when no rules match the resource."""
        # Rule for S3, but resource is EC2
        rule_item = {
            "ResourceType": {"S": "AWS::S3::Bucket"},
            "Tag": {"S": "DataClassification"},
            "Enabled": {"B": True},
            "Required": {"B": True},
            "ValuePattern": {"S": ""},
            "Values": {"S": "[]"},
            "AccountIds": {"S": '["*"]'},
        }
        mock_table_client.scan.return_value = {"Items": [rule_item]}
        mock_config_client.put_evaluations.return_value = {}

        handler.lambda_handler(sample_config_event, None)

        # Verify put_evaluations was called with NOT_APPLICABLE status
        call_args = mock_config_client.put_evaluations.call_args[1]
        assert (
            call_args["Evaluations"][0]["ComplianceType"]
            == handler.COMPLIANCE_TYPE_NOT_APPLICABLE
        )

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
