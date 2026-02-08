"""
Lambda handler for AWS Config custom rule — tagging compliance evaluation.

This function is invoked by an AWS Config custom rule. It retrieves tagging
compliance definitions from a DynamoDB table and evaluates whether the
resource under inspection carries the required tags with permitted values.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import Any, Dict, List

import boto3

# Indicates the resource is compliant with the tagging rules.
COMPLIANCE_TYPE_COMPLIANT = "COMPLIANT"
# Indicates the resource is non-compliant with the tagging rules.
COMPLIANCE_TYPE_NON_COMPLIANT = "NON_COMPLIANT"
# Indicates the tagging rules do not apply to this resource (e.g. no rules
COMPLIANCE_TYPE_NOT_APPLICABLE = "NOT_APPLICABLE"

# The DynamoDB client used to retrieve tagging rules from the DynamoDB table.
table_client = boto3.client("dynamodb")
# The AWS Config client used to report compliance evaluations back to AWS Config.
config_client = boto3.client("config")

# Module-level cache for compliance rules - persists across Lambda invocations
# within the same container (warm start). This significantly reduces DynamoDB reads.
# Thread safety note: AWS Lambda Python runtime is single-threaded per container,
# so no locking mechanism is needed for this module-level variable.
_rules_cache: dict[str, Any] = {
    "rules": None,
    "timestamp": None,
}


# Resource class representing the AWS resource being evaluated, extracted from the AWS Config event.
@dataclass
class Resource:
    # The AWS account ID that owns the resource being evaluated.
    AccountId: str
    # The AWS resource type being evaluated.
    ResourceType: str
    # The unique identifier of the resource being evaluated.
    ResourceId: str
    # The tags associated with the resource being evaluated, represented as a dict
    Tags: Dict[str, str] = field(default_factory=dict)

    def contains(self, tag_key: str) -> bool:
        """
        Check if the resource contains a specific tag key.

        Args:
            tag_key: The key of the tag to check for.
        Returns:
            True if the tag key is present on the resource, False otherwise.
        """

        return tag_key in self.Tags

    def is_value(self, tag: str, permitted: List[str]) -> bool:
        """
        Check if the resource contains a specific tag key with a specific value.

        Args:
            tag_key: The key of the tag to check for.
            tag_value: The value of the tag to check for.

        Returns:
            True if the tag key is present on the resource and its value is in the list of
            permitted values, False otherwise.
        """

        return self.contains(tag) and self.Tags[tag] in permitted

    def is_value_pattern(self, tag: str, pattern: str) -> bool:
        """
        Check if the resource contains a specific tag key with a value that matches a regex pattern.

        Args:
            tag_key: The key of the tag to check for.
            pattern: The regex pattern that the tag value must match.

        Returns:
            True if the tag key is present on the resource and its value matches the regex pattern,
            False otherwise.
        """

        return self.contains(tag) and re.match(pattern, self.Tags[tag]) is not None


# Rule dict representing a tagging compliance rule retrieved from the DynamoDB table.
@dataclass
class Rule:
    # A list of AWS account IDs that the rule applies to. A value of "*" indicates all accounts.
    AccountIds: List[str] = field(default_factory=lambda: ["*"])
    # Whether the rule is enabled or disabled. Disabled rules are ignored.
    Enabled: bool = True
    # Whether the rule requires the tag to be present (True) or just checks if the tag value is valid if the tag is present (False).
    Required: bool = True
    # The AWS resource type that the rule applies to (e.g. "AWS::EC2::Instance").
    ResourceType: str = ""
    # An identifier for the rule, used for logging and debugging purposes.
    RuleId: str = ""
    # The key of the tag that the rule checks for (e.g. "Environment").
    Tag: str = ""
    # An optional regex pattern that the tag value must match to be considered compliant.
    ValuePattern: str = ""
    # An optional list of specific tag values that are considered compliant. If provided, the tag value must be one of these values to be compliant.
    Values: List[str] = field(default_factory=list)

    def has_values(self) -> bool:
        """Check if the rule has specific compliant values defined."""
        return bool(self.Values) and len(self.Values) > 0

    def has_value_pattern(self) -> bool:
        """Check if the rule has a compliant value pattern defined."""
        return bool(self.ValuePattern) and len(self.ValuePattern) > 0


@dataclass
class Evaluation:
    # The compliance status (COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE).
    Compliant: str = ""
    # The tag key that was evaluated.
    TagKey: str = ""
    # The tag value that was evaluated (or null if the tag is not present on the resource).
    TagValue: str = ""
    # An optional string providing details about the evaluation of this rule.
    Annotation: str = ""
    # The rule id if any specific rule was evaluated, which can be used for debugging
    # and tracing back to the rule definition.
    RuleId: str = ""


@dataclass
class Evaluations:
    # A list of evaluations for a resource against the rules
    Evaluations: List[Evaluation] = field(default_factory=list)

    def is_compliant(self) -> bool:
        """
        Checks if the evaluation contains any non-compliant results, while ensuring that
        if the resource is marked as not applicable, we return false for compliant.

        Returns:
            True if all evaluations are compliant and the resource is not marked as not applicable, False otherwise
        """

        # Ensure we return false to non-applicable resources
        if self.is_non_applicable():
            return False

        return all(
            evaluation.Compliant == COMPLIANCE_TYPE_COMPLIANT
            for evaluation in self.Evaluations
        )

    def is_non_applicable(self) -> bool:
        """Checks if the evaluation is marked as not applicable."""

        return all(
            evaluation.Compliant == COMPLIANCE_TYPE_NOT_APPLICABLE
            for evaluation in self.Evaluations
        )

    def add(self, evaluation: Evaluation) -> None:
        """Add an evaluation to the list of evaluations for this resource."""

        self.Evaluations.append(evaluation)

    def add_not_applicable(
        self,
        annotation: str | None = None,
        rule_id: str | None = None,
    ) -> None:
        """Mark the resource as not applicable for tagging compliance with an annotation."""

        self.add(
            Evaluation(
                Compliant=COMPLIANCE_TYPE_NOT_APPLICABLE,
                Annotation=annotation or "",
                RuleId=rule_id or "",
            )
        )

    def add_compliant(
        self,
        annotation: str,
        rule: Rule,
    ) -> None:
        """Mark the resource as compliant for tagging compliance with an annotation."""

        self.add(
            Evaluation(
                Annotation=annotation,
                Compliant=COMPLIANCE_TYPE_COMPLIANT,
                RuleId=rule.RuleId,
                TagKey=rule.Tag,
            )
        )

    def add_non_compliant(
        self,
        annotation: str,
        rule: Rule,
        value: str | None = None,
    ) -> None:
        """Mark the resource as non-compliant for tagging compliance with an annotation."""
        self.add(
            Evaluation(
                Annotation=annotation,
                Compliant=COMPLIANCE_TYPE_NON_COMPLIANT,
                RuleId=rule.RuleId,
                TagKey=rule.Tag,
                TagValue=value,
            )
        )


def parse_configuration_item(item: Dict[str, Any]) -> Resource:
    """
    Parse the configuration item from the AWS Config event into a Resource dict.

    Args:
      configuration_item: The configuration item from the AWS Config event, containing resource details.

    Returns:
      A Resource dict containing the relevant information extracted from the configuration item.
    """

    # Check for the following items
    for field_name in ["awsAccountId", "resourceType", "resourceId", "configuration"]:
        if item.get(field_name, None) is None:
            logger.error(
                "Configuration item is missing required field",
                extra={
                    "action": "parse_configuration_item",
                    "item": item,
                    "missing_field": field_name,
                },
            )
            raise ValueError(
                f"Configuration item is missing required field '{field_name}', cannot evaluate resource."
            )

    # Retrieve the tags from the configuration item, which are nested under the "configuration" key
    configuration = item.get("configuration", {})

    return Resource(
        AccountId=item.get("awsAccountId", None),
        ResourceType=item.get("resourceType", None),
        ResourceId=item.get("resourceId", None),
        Tags=configuration.get("tags", {}),
    )


def parse_rule(raw: Dict[str, Any]) -> Rule:
    """
    Parse a raw DynamoDB item into a Rule dict.

    Args:
      raw: A raw DynamoDB item representing a tagging rule.

    Returns:
      A Rule dict representing the tagging rule with keys:
        - AccountIds: List of account IDs the rule applies to.
        - Enabled: Whether the rule is enabled.
        - Required: Whether the tag is required or just validated if present.
        - ResourceType: The AWS resource type the rule applies to.
        - RuleId: An identifier for the rule, used for logging and debugging purposes.
        - Tag: The key of the tag that the rule checks for.
        - ValuePattern: An optional regex pattern that the tag value must match.
        - Values: An optional list of specific tag values that are considered compliant.
    """

    logger.debug(
        "Parsing raw DynamoDB item into Rule dict",
        extra={
            "raw_item": raw,
        },
    )

    # Parse AccountIds - it's a JSON-encoded string list in DynamoDB
    account_ids_raw = raw.get("AccountIds", {}).get("S", "")
    try:
        account_ids = json.loads(account_ids_raw) if account_ids_raw else ["*"]
    except json.JSONDecodeError:
        logger.warning(
            f"Failed to parse AccountIds JSON: {account_ids_raw}, defaulting to ['*']"
        )
        account_ids = ["*"]

    # Parse Values - it's a JSON-encoded string list in DynamoDB
    values_raw = raw.get("Values", {}).get("S", "")
    try:
        values = json.loads(values_raw) if values_raw else []
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse Values JSON: {values_raw}, defaulting to []")
        values = []

    return Rule(
        AccountIds=account_ids,
        Enabled=raw.get("Enabled", {}).get("B", True),
        Required=raw.get("Required", {}).get("B", True),
        ResourceType=raw.get("ResourceType", {}).get("S", ""),
        RuleId=raw.get("RuleId", {}).get("S", ""),
        Tag=raw.get("Tag", {}).get("S", ""),
        ValuePattern=raw.get("ValuePattern", {}).get("S", ""),
        Values=values,
    )


# Default logger for all log messages in this module, configured to emit JSON-formatted logs to stdout.
logger = logging.getLogger(__name__)
# Set the log level from the environment variable (set by Terraform) or default to INFO.
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())


class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON object."""

    # Standard fields that are part of every LogRecord
    _STANDARD_RECORD_FIELDS = {
        "name",
        "msg",
        "args",
        "created",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "thread",
        "threadName",
        "exc_info",
        "exc_text",
        "stack_info",
        "asctime",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include extra fields from the record
        for key, value in record.__dict__.items():
            if key not in self._STANDARD_RECORD_FIELDS:
                log_entry[key] = value

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


_handler = logging.StreamHandler()
_handler.setFormatter(_JSONFormatter())
logger.handlers = [_handler]
logger.propagate = False


def get_rules(
    table_arn: str, enable_cache: bool = False, cache_ttl_seconds: int = 3600
) -> List[Rule]:
    """
    Retrieve tagging rules from cache or DynamoDB with automatic cache expiration.

    This function implements a module-level cache that persists across Lambda invocations
    within the same container (warm start). Cache hits can reduce DynamoDB read capacity
    by 80-90% for typical workloads. The downside is changes to the rules will take
    up to the cache TTL to propagate to all Lambda instances, but this is usually an acceptable
    tradeoff for the cost savings.

    Caching behavior can be controlled via:
    - enable_cache parameter for per-invocation override (e.g., from event payload)

    Args:
      table_arn: The ARN of the DynamoDB table containing tagging rules.
      enable_cache: If True, enable the cache and fetch from cache if valid.

    Returns:
      A list of Rule objects representing the tagging rules.
    """

    # Extract the table name from the ARN (format: arn:aws:dynamodb:region:account-id:table/TableName)
    table_name = table_arn.split("/")[-1]

    logger.info(
        "Retrieving compliance rules",
        extra={
            "action": "get_rules",
            "cache_ttl_seconds": cache_ttl_seconds,
            "enable_cache": enable_cache,
            "table_name": table_name,
        },
    )

    # Get the current time to compare against the cache timestamp for expiration
    now = datetime.now(timezone.utc).timestamp()

    # Check if caching is enabled before attempting to use the cache
    if enable_cache:
        if (
            _rules_cache["rules"] is not None
            and _rules_cache["timestamp"] is not None
            and (now - _rules_cache["timestamp"]) < cache_ttl_seconds
        ):
            logger.info(
                "Cache has results, using cached rules",
                extra={
                    "action": "get_rules",
                    "cache_age_seconds": round(now - _rules_cache["timestamp"], 2),
                },
            )

            return _rules_cache["rules"]

        else:
            logger.info(
                "Cache miss or expired, fetching from DynamoDB",
                extra={
                    "action": "get_rules",
                    "cache_ttl_seconds": cache_ttl_seconds,
                    "enable_cache": enable_cache,
                },
            )

    rules = []
    # Retrieve only enabled rules from the DynamoDB table with server-side filtering to reduce
    # data transfer and parsing overhead. This can reduce costs and improve performance significantly
    # when there are many disabled rules in the table.
    response = table_client.scan(
        TableName=table_name,
        FilterExpression="Enabled = :enabled_value",
        ExpressionAttributeValues={":enabled_value": {"BOOL": True}},
    )
    # Iterate over the items in the response and parse each one into a tagging rule dict.
    for item in response.get("Items", []):
        rules.append(parse_rule(item))

    # Add the results to the cache if required
    if enable_cache:
        _rules_cache["rules"] = rules
        _rules_cache["timestamp"] = now

        logger.info(
            "Compliance rules cached",
            extra={
                "action": "get_rules",
                "cache_ttl_seconds": cache_ttl_seconds,
                "rule_count": len(rules),
            },
        )

    return rules


def find_matching_rules(
    rules: List[Rule],
    resource: Resource,
) -> List[Rule]:
    """
    Find all tagging rules that apply to the given resource type.

    Args:
      rules: A list of dicts representing the tagging rules to check against.
      resource: The AWS resource type being evaluated (e.g. "AWS::EC2::Instance").

    Returns:
      A list of dicts representing the tagging rules that apply to the resource type.
    """

    # A list of rules that apply to the resource type being evaluated.
    matching_rules = []

    for rule in rules:
        # First we check if the rule is enabled, if not we skip it.
        if not rule.Enabled:
            continue
        # Next we check if the rule matches the account or wildcard, if not we skip it.
        if rule.AccountIds != ["*"] and resource.AccountId not in rule.AccountIds:
            continue
        # Next we check if the rule matches the resource type or wildcard, if not we skip it.
        # Support wildcard matching: "AWS::EC2::*" matches "AWS::EC2::Instance"
        if not (
            rule.ResourceType == "*"
            or resource.ResourceType == rule.ResourceType
            or rule.ResourceType.endswith("*")
            and resource.ResourceType.startswith(rule.ResourceType[:-1])
        ):
            continue

        # We have a match, lets add it to the list of matching rules for this resource type
        matching_rules.append(rule)

    logger.info(
        "Found matching tagging rules for resource",
        extra={
            "action": "find_matching_rules",
            "account_id": resource.AccountId,
            "resource_id": resource.ResourceId,
            "resource_type": resource.ResourceType,
            "matching_rule_count": len(matching_rules),
        },
    )

    return matching_rules


def validate_compliance(
    rules: List[Rule],
    resource: Resource,
) -> Evaluations:
    """
    Check if a resource complies with the given tagging rules.

    Args:
        rules: A list of Rule dicts representing the tagging rules to check against.
        resource: A Resource dict representing the AWS resource being evaluated.

    Returns:
        A list of RuleEvaluation dicts representing the evaluation of each rule against the resource,
        including whether the resource is compliant with each rule and any relevant annotations.
    """

    # Iterate the rules and ensure we match all the requirements
    conditions = Evaluations()

    logger.info(
        "Evaluating resource compliance with tagging rules",
        extra={
            "action": "validate_compliance",
            "account_id": resource.AccountId,
            "resource_id": resource.ResourceId,
            "resource_type": resource.ResourceType,
            "rule_count": len(rules),
        },
    )

    for rule in rules:
        # Get the tag in question from the rule
        tag = rule.Tag
        # Check if the tag is present on the resource and get its value (or null if not present)
        if not resource.contains(tag) and rule.Required:
            conditions.add_non_compliant(
                annotation="Required tag is missing",
                rule=rule,
            )

        if resource.contains(tag):
            if rule.has_values() and not resource.is_value(tag, rule.Values):
                conditions.add_non_compliant(
                    annotation=f"Tag value does not match any of the permitted values: {rule.Values}",
                    rule=rule,
                    value=resource.Tags[tag],
                )

            if rule.has_value_pattern() and not resource.is_value_pattern(
                tag, rule.ValuePattern
            ):
                conditions.add_non_compliant(
                    annotation=f"Tag value does not match the required pattern: {rule.ValuePattern}",
                    rule=rule,
                    value=resource.Tags[tag],
                )
        elif not rule.Required and not resource.contains(tag):
            # For optional tags that are not present, mark as compliant
            conditions.add_compliant(
                annotation="Optional tag not present (compliant)",
                rule=rule,
            )

    logger.info(
        "Completed evaluation of resource compliance with tagging rules",
        extra={
            "action": "validate_compliance",
            "account_id": resource.AccountId,
            "condition_count": len(conditions.Evaluations),
            "resource_id": resource.ResourceId,
            "resource_type": resource.ResourceType,
        },
    )

    # If no evaluations were added (all required tags are present and valid), mark as compliant
    if not conditions.Evaluations:
        conditions.add_compliant(
            annotation="All required tags are present and valid",
            rule=Rule(
                RuleId="all_required_tags_present",
                Required=True,
            ),
        )

    return conditions


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

    for var_name in ["ACCOUNT_ID", "TABLE_ARN"]:
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
    """

    # Validate the event contains the required fields before processing
    validate_configuration_event(event)
    # Validate the required environment variables are set before processing
    validate_environment()

    # Get the account id from the environment variable (set by Terraform) or from the event
    account_id = event.get("accountId") or os.environ.get("ACCOUNT_ID")
    # Get the table ARN from the environment variable (set by Terraform)
    table_arn = event.get("table_arn") or os.environ.get("TABLE_ARN")
    # Enable the rules caching from environment variable
    enable_cache = os.environ.get("RULES_CACHE_ENABLED", "false").lower() == "true"
    # Check if the event has an override to the cache setting
    if "enable_cache" in event:
        # Apply the override from the event if any
        enable_cache = event["enable_cache"].lower() == "true"
    # Get the cache TTL from environment variable or default to 3600 seconds (1 hour)
    cache_ttl_seconds = int(os.environ.get("RULES_CACHE_TTL_SECONDS", "3600"))

    # Get the result token from the event, which is used to report compliance results back to AWS Config.
    token = event["resultToken"]

    logger.info(
        "Processing AWS Config event",
        extra={
            "action": "lambda_handler",
            "account_id": account_id,
            "event": event,
        },
    )

    # Extract relevant information from the event
    invoking_event = json.loads(event.get("invokingEvent", "{}"))
    # The configuration item contains details about the resource being evaluated.
    configuration_item = invoking_event.get("configurationItem", {})
    # Parse the configuration item into a Resource dict for easier handling.
    resource = parse_configuration_item(configuration_item)
    # Is a list of evaluations for each rule that applies to this resource,
    # which we will populate as we evaluate the rules.
    evaluations = Evaluations()

    # If the resource is being deleted or was deleted without a recorded configuration, we cannot evaluate tags.
    if configuration_item.get("configurationItemStatus") in (
        "ResourceDeletedNotRecorded",
        "ResourceDeleted",
    ):
        logger.info(
            "Resource deleted, marking NOT_APPLICABLE",
            extra={
                "action": "lambda_handler",
                "account_id": account_id,
                "resource_id": resource.ResourceId,
            },
        )
        # We have nothing to evaluate, so we return NOT_APPLICABLE for this resource and exit early.
        evaluations.add_not_applicable(
            annotation="Resource has been deleted, ignoring tagging compliance."
        )

    else:
        # Retrieve the rules from the DynamoDB table
        rules = get_rules(
            cache_ttl_seconds=cache_ttl_seconds,
            enable_cache=enable_cache,
            table_arn=table_arn,
        )
        # Find matching rules for the resource
        matching_rules = find_matching_rules(rules, resource)
        # If there are no matching rules, we consider the resource NOT_APPLICABLE for tagging compliance and return early.
        if not matching_rules:
            logger.info(
                "No matching tagging rules found for resource, marking NOT_APPLICABLE",
                extra={
                    "action": "lambda_handler",
                    "account_id": resource.AccountId,
                    "resource_id": resource.ResourceId,
                    "resource_type": resource.ResourceType,
                },
            )
            evaluations.add_not_applicable(
                annotation="No applicable tagging rules found for this resource type."
            )
        else:
            # Evaluate the resource against the matching rules and determine compliance.
            evaluations = validate_compliance(matching_rules, resource)

    # Log the evaluations for debugging purposes before reporting to AWS Config
    if not evaluations.is_compliant():
        logger.info(
            "Resource is non-compliant with tagging rules",
            extra={
                "action": "lambda_handler",
                "account_id": resource.AccountId,
                "resource_id": resource.ResourceId,
                "resource_type": resource.ResourceType,
            },
        )

        # Print each of the evaluations that resulted in non-compliance for debugging
        for evaluation in evaluations.Evaluations:
            if evaluation.Compliant == COMPLIANCE_TYPE_NON_COMPLIANT:
                logger.info(
                    "Resource is non-compliant with tagging rule",
                    extra={
                        "action": "lambda_handler",
                        "account_id": resource.AccountId,
                        "annotation": evaluation.Annotation,
                        "resource_id": resource.ResourceId,
                        "resource_type": resource.ResourceType,
                        "rule_id": evaluation.RuleId,
                        "tag_key": evaluation.TagKey,
                        "tag_value": evaluation.TagValue,
                    },
                )

    if evaluations.is_non_applicable():
        compliance_type = COMPLIANCE_TYPE_NOT_APPLICABLE
        annotation = "Resource is not applicable for tagging compliance."
    elif evaluations.is_compliant():
        compliance_type = COMPLIANCE_TYPE_COMPLIANT
        annotation = "Resource is compliant with tagging rules."
    else:
        compliance_type = COMPLIANCE_TYPE_NON_COMPLIANT
        annotation = "Resource is non-compliant with tagging rules. See evaluation details for more information."

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

    logger.info(
        "Evaluation of resource compliance with tagging rules reported to AWS Config",
        extra={
            "action": "lambda_handler",
            "compliance_type": compliance_type,
            "resource_id": resource.ResourceId,
        },
    )
