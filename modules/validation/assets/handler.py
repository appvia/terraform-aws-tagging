"""
Lambda handler for AWS Config custom rule — tagging compliance evaluation.

This function is invoked by an AWS Config custom rule. It loads a YAML tagging
policy from S3 and evaluates whether the resource under inspection complies with
the policy rules.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, FrozenSet, Optional, Set, Tuple

import boto3

import store
from engine import Account, Subject, check_subject
from policy import Policy
from store import Mappings

# Indicates the resource is compliant with the tagging rules.
COMPLIANCE_TYPE_COMPLIANT = "COMPLIANT"
# Indicates the resource is non-compliant with the tagging rules.
COMPLIANCE_TYPE_NON_COMPLIANT = "NON_COMPLIANT"
# Indicates the tagging rules do not apply to this resource.
COMPLIANCE_TYPE_NOT_APPLICABLE = "NOT_APPLICABLE"

# Maximum annotation length for AWS Config evaluations
MAX_ANNOTATION = 256

# Fixed annotation for compliant resources
COMPLIANT_ANNOTATION = "Resource is compliant with tagging rules"

# The AWS Config client used to report compliance evaluations back to AWS Config.
config_client = boto3.client("config")

# Module-level set to track which rule sets we've logged the "rules ignored" message for
_logged_skipped_rules: Set[FrozenSet[str]] = set()


# Resource class representing the AWS resource being evaluated, extracted from the AWS Config event.
@dataclass
class Resource:
    # The AWS account ID that owns the resource being evaluated.
    AccountId: str
    # The ARN of the resource being evaluated.
    ARN: str
    # The AWS resource type being evaluated.
    ResourceType: str
    # The unique identifier of the resource being evaluated.
    ResourceId: str
    # The tags associated with the resource being evaluated, represented as a dict
    Tags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: Dict[str, Any]) -> "Resource":
        """Parse the AWS Config configuration item to return a Resource object."""
        # Check for the following items; note neither 'configuration' nor 'ARN' are
        # required, as AWS Config sends both as null for deleted resources
        # (ResourceDeleted). The ARN is only used for logging and ARN based
        # exclusions, so an empty value is safe to evaluate against.
        for field_name in [
            "awsAccountId",
            "resourceId",
            "resourceType",
        ]:
            if raw.get(field_name, None) is None:
                raise ValueError(
                    f"Configuration item is missing required field '{field_name}', cannot evaluate resource."
                )

        # Retrieve the tags from the configuration item. AWS Config reports these in
        # two places: some resource types (EC2 among them) embed them in the
        # "configuration" blob, while the configuration item itself always carries a
        # top level "tags" map. We read both, so resource types that only populate
        # one of them are still evaluated against the tags they actually carry.
        tags = {}
        configuration = raw.get("configuration") or {}

        # Tags embedded in the configuration blob are a list of {key, value} pairs
        for tag in configuration.get("tags") or []:
            if "key" in tag and "value" in tag:
                tags[tag["key"]] = tag["value"]

        # Tags on the configuration item itself are a plain key to value map, and are
        # the canonical source, so they take precedence where both are populated
        for tag_key, tag_value in (raw.get("tags") or {}).items():
            tags[tag_key] = tag_value

        return cls(
            AccountId=raw.get("awsAccountId", None),
            ARN=raw.get("ARN") or "",
            ResourceType=raw.get("resourceType", None),
            ResourceId=raw.get("resourceId", None),
            Tags=tags,
        )


# Default logger for all log messages in this module, configured to emit JSON-formatted logs to stdout.
logger = logging.getLogger(__name__)
# Set the log level from the environment variable (set by Terraform) or default to INFO.
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())


class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON object."""

    # Standard Python logging record fields to exclude from output
    _EXCLUDE_FIELDS = {
        "name",
        "msg",
        "args",
        "created",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "module",
        "msecs",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "exc_info",
        "exc_text",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include only extra fields (exclude standard logging record attributes)
        for key, value in record.__dict__.items():
            if key not in self._EXCLUDE_FIELDS:
                log_entry[key] = value

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


_handler = logging.StreamHandler()
_handler.setFormatter(_JSONFormatter())
logger.handlers = [_handler]
logger.propagate = False


def filter_on_resources(
    resource: Resource,
) -> bool:
    """
    Filter function to determine if we should evaluate the resource for
    tagging compliance based on its type.

    Args:
        resource: The AWS resource being evaluated.

    Returns:
        True if the resource should be evaluated for tagging compliance, False otherwise.
    """

    if resource.ResourceType.startswith("AWS::IAM::Role"):
        # We can skip anything related to AWS Managed Roles
        for item in [
            "aws-controltower",
            "aws-reserved/sso.amazonaws.com",
            "aws-service-role",
            "AWSControlTower",
        ]:
            if resource.ARN and item in resource.ARN:
                logger.info(
                    "Skipping AWS managed IAM roles",
                    extra={
                        "action": "filter_on_resources",
                        "account_id": resource.AccountId,
                        "resource_id": resource.ResourceId,
                        "resource_type": resource.ResourceType,
                    },
                )
                return True

    return False


def evaluate(
    resource: Resource,
    policy: Policy,
    mappings: Mappings,
    inventory: Optional[Dict[str, Account]],
) -> Tuple[str, str]:
    """
    Evaluate a resource against a policy.

    Args:
        resource: The AWS resource to evaluate
        policy: The tagging policy
        mappings: The type mappings (Terraform <-> Config)
        inventory: Optional account inventory

    Returns:
        Tuple of (compliance_type, annotation)
    """

    # Check if the resource type is taggable (appears in mappings)
    if not mappings.taggable(resource.ResourceType):
        return (
            COMPLIANCE_TYPE_NOT_APPLICABLE,
            f"Resource type {resource.ResourceType} is not taggable",
        )

    # Check if the resource type is excluded
    # exclude_resource_types may contain Terraform names or AWS:: names
    is_excluded = False
    if resource.ResourceType in policy.exclude_resource_types:
        # Direct AWS:: name match
        is_excluded = True
    else:
        # Check if any Terraform name in the exclusion list maps to this Config type
        terraform_types = mappings.to_terraform.get(resource.ResourceType, ())
        for tf_type in terraform_types:
            if tf_type in policy.exclude_resource_types:
                is_excluded = True
                break

    if is_excluded:
        return (
            COMPLIANCE_TYPE_NOT_APPLICABLE,
            f"Resource type {resource.ResourceType} is excluded from evaluation",
        )

    # Build the Subject
    terraform_types = mappings.to_terraform.get(resource.ResourceType, ())
    account = None
    if inventory is not None:
        account = inventory.get(resource.AccountId)
        if account is None:
            # Account exists in AWS but not in inventory - log warning once per call
            logger.warning(
                "Account not found in inventory",
                extra={
                    "action": "evaluate",
                    "account_id": resource.AccountId,
                    "resource_type": resource.ResourceType,
                },
            )

    subject = Subject(
        config_type=resource.ResourceType,
        terraform_types=terraform_types,
        tags=resource.Tags,
        account_id=resource.AccountId,
        account=account,
    )

    # Run the policy engine
    outcome = check_subject(policy, subject)

    # Log when rules are skipped due to missing inventory, deduplicating by the set of skipped rules
    if outcome.skipped_rules:
        skipped_key = frozenset(outcome.skipped_rules)
        if skipped_key not in _logged_skipped_rules:
            _logged_skipped_rules.add(skipped_key)
            logger.info(
                "Rules skipped due to missing account inventory",
                extra={
                    "action": "evaluate",
                    "skipped_rules": list(outcome.skipped_rules),
                    "resource_type": resource.ResourceType,
                    "account_id": resource.AccountId,
                },
            )

    # Log warnings
    for violation in outcome.violations:
        if violation.severity == "warning":
            logger.warning(
                "Policy warning",
                extra={
                    "action": "evaluate",
                    "rule": violation.rule,
                    "violation_message": violation.message,
                    "resource_type": resource.ResourceType,
                    "resource_id": resource.ResourceId,
                },
            )

    # Map outcome to Config compliance type
    error_violations = [v for v in outcome.violations if v.severity == "error"]

    if error_violations:
        # Any error violation → NON_COMPLIANT
        # Annotation format: "<rule>: <message>; <rule>: <message>..."
        parts = [f"{v.rule}: {v.message}" for v in error_violations]
        annotation = "; ".join(parts)
        # Truncate to MAX_ANNOTATION ending in "..." if longer
        if len(annotation) > MAX_ANNOTATION:
            annotation = annotation[: MAX_ANNOTATION - 3] + "..."
        return (COMPLIANCE_TYPE_NON_COMPLIANT, annotation)

    if not outcome.asserted:
        # No rule reached an assert → NOT_APPLICABLE
        return (
            COMPLIANCE_TYPE_NOT_APPLICABLE,
            "No applicable rules reached for this resource",
        )

    # Otherwise COMPLIANT (including warning-only cases)
    return (COMPLIANCE_TYPE_COMPLIANT, COMPLIANT_ANNOTATION)


def validate_configuration_event(event: dict[str, Any]) -> None:
    """
    Validate that the AWS Config event contains the required fields for processing.

    Args:
        event: The AWS Config event payload to validate.

    Raises:
        ValueError: If any required fields are missing from the event.
    """

    fields = [
        "invokingEvent",
        "resultToken",
        "accountId",
        "configRuleArn",
        "configRuleId",
    ]
    for field in fields:
        if field not in event:
            logger.error(
                "AWS Config event is missing required field",
                extra={
                    "missing_field": field,
                    "event": event,
                },
            )
            raise ValueError(f"AWS Config event is missing required field: {field}")


def validate_environment() -> None:
    """
    Ensure that all required environment variables are set before processing the event.

    Raises:
        ValueError: If any required environment variables are missing.
    """

    for var_name in ["POLICY_BUCKET"]:
        if not os.environ.get(var_name):
            logger.error(
                "Missing required environment variable",
                extra={"var_name": var_name},
            )
            raise ValueError(
                f"Environment variable {var_name} is required but not set."
            )


def lambda_handler(event: dict[str, Any], context: Any) -> None:
    """
    AWS Lambda handler invoked by an AWS Config custom rule.

    Args:
        event: The AWS Config event payload containing details about the resource
               being evaluated and the rule parameters.
        context: The AWS Lambda execution context (not used in this function).

    Returns:
        None. The function reports compliance results back to AWS Config via
        put_evaluations.
    """

    # Validate the event contains the required fields before processing
    validate_configuration_event(event)
    # Validate the required environment variables are set before processing
    validate_environment()

    # Get environment variables
    policy_bucket = os.environ.get("POLICY_BUCKET")
    policy_key = os.environ.get("POLICY_KEY", "policy.yaml")
    mappings_key = os.environ.get("MAPPINGS_KEY", "mappings.yaml")
    accounts_key = os.environ.get("ACCOUNTS_KEY", "")
    # Empty string for accounts_key means no inventory
    if not accounts_key:
        accounts_key = None

    # Get cache settings
    cache_enabled = os.environ.get("RULES_CACHE_ENABLED", "false").lower() == "true"
    # Check if the event has an override to the cache setting
    if "enable_cache" in event:
        cache_enabled = event["enable_cache"]
    cache_ttl_seconds = int(os.environ.get("RULES_CACHE_TTL_SECONDS", "3600"))

    # Configure cache
    store.configure_cache(cache_enabled, cache_ttl_seconds)

    # Get the result token from the event
    token = event["resultToken"]

    logger.info(
        "Processing AWS Config event",
        extra={
            "action": "lambda_handler",
            "policy_bucket": policy_bucket,
            "policy_key": policy_key,
            "mappings_key": mappings_key,
            "accounts_key": accounts_key,
            "cache_enabled": cache_enabled,
            "cache_ttl_seconds": cache_ttl_seconds,
            "config_event": event,
        },
    )

    # Extract relevant information from the event
    invoking_event = json.loads(event.get("invokingEvent", "{}"))
    configuration_item = invoking_event.get("configurationItem", {})
    resource = Resource.parse(configuration_item)

    # If the resource is being deleted or was deleted without a recorded configuration, we cannot evaluate tags.
    if configuration_item.get("configurationItemStatus") in (
        "ResourceDeletedNotRecorded",
        "ResourceDeleted",
    ):
        logger.info(
            "Resource deleted, marking NOT_APPLICABLE",
            extra={
                "action": "lambda_handler",
                "account_id": resource.AccountId,
                "resource_id": resource.ResourceId,
                "resource_type": resource.ResourceType,
            },
        )
        compliance_type = COMPLIANCE_TYPE_NOT_APPLICABLE
        annotation = "Resource has been deleted, ignoring tagging compliance"

    # Check if we should skip this resource based on filtering rules
    elif filter_on_resources(resource):
        logger.info(
            "Resource filtered, marking NOT_APPLICABLE",
            extra={
                "action": "lambda_handler",
                "account_id": resource.AccountId,
                "resource_id": resource.ResourceId,
                "resource_type": resource.ResourceType,
            },
        )
        compliance_type = COMPLIANCE_TYPE_NOT_APPLICABLE
        annotation = "Resource type is excluded from tagging compliance evaluation based on its ARN or type"

    else:
        # Load policy, mappings, and inventory from S3
        # If any of these raises an error (e.g., PolicyError), the Lambda will fail
        # and AWS Config will retry. We do NOT put_evaluations in error cases.
        policy = store.load_policy(policy_bucket, policy_key)
        mappings = store.load_mappings(policy_bucket, mappings_key)
        inventory = store.load_inventory(policy_bucket, accounts_key)

        logger.debug(
            "Loaded policy and mappings",
            extra={
                "action": "lambda_handler",
                "policy_rules_count": len(policy.rules),
                "policy_excluded_types": list(policy.exclude_resource_types),
                "mappings_count": len(mappings.to_config),
                "inventory_accounts_count": len(inventory) if inventory else 0,
            },
        )

        # Evaluate the resource against the policy
        compliance_type, annotation = evaluate(resource, policy, mappings, inventory)

    # Log the compliance result
    logger.info(
        "Compliance evaluation completed for resource",
        extra={
            "action": "lambda_handler",
            "account_id": resource.AccountId,
            "compliance_status": compliance_type,
            "resource_arn": resource.ARN,
            "resource_id": resource.ResourceId,
            "resource_tags": resource.Tags,
            "resource_type": resource.ResourceType,
            "annotation": annotation,
        },
    )

    # Report the compliance evaluation back to AWS Config using the result token from the event.
    config_client.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource.ResourceType,
                "ComplianceResourceId": resource.ResourceId,
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                "OrderingTimestamp": datetime.now(tz=timezone.utc),
            }
        ],
        ResultToken=token,
    )
