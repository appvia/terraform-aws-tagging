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
_cache: dict[str, Any] = {
    "rules": None,
    "rules_timestamp": None,
}


@dataclass
class AccountMetadata:
    # The AWS account ID that owns the resource being evaluated.
    AccountId: str
    # Name of the AWS account that owns the resource being evaluated.
    AccountName: str
    # The organizational unit path of the AWS account that owns the resource being evaluated (e.g. "root/engineering/platform").
    OUPath: str
    # The status of the AWS account that owns the resource being evaluated (e.g. "ACTIVE", "SUSPENDED").
    Status: str

    @classmethod
    def parse(cls, raw: Dict[str, Any]) -> "AccountMetadata":
        """Parse a raw DynamoDB item into an AccountMetadata object."""

        logger.debug(
            "Parsing account metadata from DynamoDB item",
            extra={
                "action": "AccountMetadata.parse",
                "raw_item": raw,
            },
        )

        # Ensure we have the required fields in the raw item
        for field_name in ["AccountId", "AccountName", "OUPath", "Status"]:
            if raw.get(field_name, None) is None:
                raise ValueError(
                    f"Item is missing required field '{field_name}' for AccountMetadata."
                )

        return cls(
            AccountId=raw.get("AccountId", {}).get("S", ""),
            AccountName=raw.get("AccountName", {}).get("S", ""),
            OUPath=raw.get("OUPath", {}).get("S", ""),
            Status=raw.get("Status", {}).get("S", ""),
        )


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

    @classmethod
    def parse(cls, raw: Dict[str, Any]) -> "Resource":
        """Parse the AWS Config configuration item to return a Resource object."""
        # Check for the following items
        for field_name in [
            "awsAccountId",
            "resourceType",
            "resourceId",
            "configuration",
        ]:
            if raw.get(field_name, None) is None:
                raise ValueError(
                    f"Configuration item is missing required field '{field_name}', cannot evaluate resource."
                )

        # Retrieve the tags from the configuration item, which are nested under the "configuration" key
        configuration = raw.get("configuration", {})

        return cls(
            AccountId=raw.get("awsAccountId", None),
            ResourceType=raw.get("resourceType", None),
            ResourceId=raw.get("resourceId", None),
            Tags=configuration.get("tags", {}),
        )

    def contains_tag(self, tag_key: str) -> bool:
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

        return self.contains_tag(tag) and self.Tags[tag] in permitted

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

        return self.contains_tag(tag) and re.match(pattern, self.Tags[tag]) is not None


# Rule dict representing a tagging compliance rule retrieved from the DynamoDB table.
@dataclass
class Rule:
    # A list of AWS account IDs that the rule applies to. A value of "*" indicates all accounts.
    AccountIds: List[str] = field(default_factory=lambda: ["*"])
    # Whether the rule is enabled or disabled. Disabled rules are ignored.
    Enabled: bool = True
    # OrganizationalPaths is an optional list of organizational unit paths that the rule applies to. A value of "*" indicates all OUs.
    OrganizationalPaths: List[str] = field(default_factory=list)
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

    @classmethod
    def parse(cls, raw: Dict[str, Any]) -> "Rule":
        """Parse a raw DynamoDB item into a Rule object."""

        return cls(
            AccountIds=json.loads(raw.get("AccountIds", {}).get("S", '["*"]')),
            Enabled=raw.get("Enabled", {}).get("B", True),
            OrganizationalPaths=json.loads(
                raw.get("OrganizationalPaths", {}).get("S", "[]")
            ),
            Required=raw.get("Required", {}).get("B", True),
            ResourceType=raw.get("ResourceType", {}).get("S", ""),
            RuleId=raw.get("RuleId", {}).get("S", ""),
            Tag=raw.get("Tag", {}).get("S", ""),
            ValuePattern=raw.get("ValuePattern", {}).get("S", ""),
            Values=json.loads(raw.get("Values", {}).get("S", "[]")),
        )

    def has_values(self) -> bool:
        """Check if the rule has specific compliant values defined."""
        return bool(self.Values) and len(self.Values) > 0

    def has_value_pattern(self) -> bool:
        """Check if the rule has a compliant value pattern defined."""
        return bool(self.ValuePattern) and len(self.ValuePattern) > 0

    def has_organizational_paths(self) -> bool:
        """Check if the rule has organizational paths defined."""
        return bool(self.OrganizationalPaths) and len(self.OrganizationalPaths) > 0

    def is_inside_organizational_path(self, path: str) -> bool:
        """Check if the resource's account is within any of the organizational paths"""
        return "*" in self.OrganizationalPaths or any(
            path.startswith(org_path) for org_path in self.OrganizationalPaths
        )


@dataclass
class Evaluation:
    # The compliance status (COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE).
    Compliant: str = ""
    # The tag key that was evaluated.
    TagKey: str = ""
    # The tag value that was evaluated (or null if the tag is not present on the resource).
    TagValue: str | None = None
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

    def get_non_compliance_reasons(self) -> List[str]:
        """Get a list of annotations for all non-compliant evaluations."""

        return [
            evaluation.Annotation
            for evaluation in self.Evaluations
            if evaluation.Compliant == COMPLIANCE_TYPE_NON_COMPLIANT
        ]


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


def get_cached(key: str, ttl_seconds: int = 3600) -> Any | None:
    """
    Retrieve a value from the cache if it exists and is not expired.

    Args:
        key: The key of the cached value to retrieve.

    Returns:
        The cached value if it exists and is not expired, or None if the cache is missing or expired.
    """

    now = datetime.now(timezone.utc).timestamp()
    cache_timestamp_key = f"{key}_timestamp"

    if (
        _cache.get(key) is not None
        and _cache.get(cache_timestamp_key) is not None
        and (now - _cache[cache_timestamp_key]) < ttl_seconds
    ):
        logger.info(
            "Cache hit for key",
            extra={
                "action": "get_cached",
                "key": key,
                "cache_age_seconds": round(now - _cache[cache_timestamp_key], 2),
            },
        )
        return _cache[key]
    else:
        logger.info(
            "Cache miss or expired for key",
            extra={
                "action": "get_cached",
                "key": key,
            },
        )
        return None


def set_cached(key: str, value: Any) -> None:
    """
    Set a value in the cache with the current timestamp.

    Args:
        key: The key of the cached value to set.
        value: The value to cache.
    """

    logger.debug(
        "Setting cache value for key",
        extra={
            "action": "set_cached",
            "key": key,
        },
    )

    now = datetime.now(timezone.utc).timestamp()
    _cache[key] = value
    _cache[f"{key}_timestamp"] = now


def get_account(
    account_id: str,
    table_arn: str,
    enable_cache: bool = False,
    ttl_seconds: int = 21600,
) -> AccountMetadata:
    """
    Retrieve organizational unit paths for accounts from cache or DynamoDB with automatic cache expiration.

    Args:
        account_id: The AWS account ID to retrieve organizational paths for.
        enable_cache: If True, enable the cache and fetch from cache if valid.
        table_arn: The ARN of the DynamoDB table containing organizational data.

    Returns:
        An AccountMetadata object containing the organizational data for the specified account.
    """

    # Extract the table name from the ARN (format: arn:aws:dynamodb:region:account-id:table/TableName)
    logger.info(
        "Retrieving account data",
        extra={
            "action": "get_account",
            "enable_cache": enable_cache,
            "table_arn": table_arn,
            "ttl_seconds": ttl_seconds,
        },
    )
    # Use an account id as a cache key to ensure we can cache organizational data
    # for multiple accounts if needed in the future
    cache_key = f"{account_id}_account"

    # Check if caching is enabled before attempting to use the cache
    if enable_cache:
        cached = get_cached(cache_key, ttl_seconds)
        if cached is not None:
            return cached

    # Retrieve organizational data for this account
    response = table_client.query(
        TableName=table_arn,
        KeyConditionExpression="AccountId = :account_id",
        ExpressionAttributeValues={":account_id": {"S": account_id}},
    )
    if response.get("Count", 0) == 0:
        logger.warning(
            "No organizational data found for account",
            extra={
                "action": "get_account",
                "account_id": account_id,
                "table_arn": table_arn,
            },
        )
        raise ValueError(
            f"No organizational data found for account {account_id} in table {table_arn}."
        )

    # Parse the organizational data into an AccountMetadata object
    account = AccountMetadata.parse(response["Items"][0])
    if enable_cache:
        set_cached(cache_key, account)

    return account


def get_rules(
    table_arn: str,
    enable_cache: bool = False,
    ttl_seconds: int = 3600,
) -> List[Rule]:
    """
    Retrieve tagging rules from cache or DynamoDB with automatic cache expiration.

    This function implements a module-level cache that persists across Lambda invocations
    within the same container (warm start). Cache hits can reduce DynamoDB read capacity
    by 80-90% for typical workloads. The downside is changes to the rules will take
    up to the cache TTL to propagate to all Lambda instances, but this is usually an acceptable
    tradeoff for the cost savings.

    Args:
        table_arn: The ARN of the DynamoDB table containing tagging rules.
        enable_cache: If True, enable the cache and fetch from cache if valid.
        ttl_seconds: The time-to-live for cache entries in seconds.

    Returns:
        A list of Rule objects representing the tagging rules.
    """

    logger.info(
        "Retrieving compliance rules",
        extra={
            "action": "get_rules",
            "enable_cache": enable_cache,
            "table_arn": table_arn,
            "ttl_seconds": ttl_seconds,
        },
    )
    # Check if caching is enabled before attempting to use the cache
    if enable_cache:
        cached = get_cached("rules", ttl_seconds)
        if cached is not None:
            return cached

    rules = []
    # Retrieve only enabled rules from the DynamoDB table with server-side filtering to reduce
    # data transfer and parsing overhead. This can reduce costs and improve performance significantly
    # when there are many disabled rules in the table.
    response = table_client.scan(
        TableName=table_arn,
        FilterExpression="Enabled = :enabled_value",
        ExpressionAttributeValues={":enabled_value": {"BOOL": True}},
    )
    # Iterate over the items in the response and parse each one into a tagging rule dict.
    for item in response.get("Items", []):
        rules.append(Rule.parse(item))

    # Add the results to the cache if required
    if enable_cache:
        set_cached("rules", rules)

    return rules


def find_matching_rules(
    rules: List[Rule],
    resource: Resource,
    account: AccountMetadata | None = None,
) -> List[Rule]:
    """
    Find all tagging rules that apply to the given resource type.

    Args:
      rules: A list of Rule objects representing the tagging rules to check against.
      resource: The AWS resource type being evaluated (e.g. "AWS::EC2::Instance").

    Returns:
      A list of Rule objects representing the tagging rules that apply to the resource type.
    """

    logger.info(
        "Finding matching rules for resource",
        extra={
            "action": "find_matching_rules",
            "account_id": resource.AccountId,
            "resource_id": resource.ResourceId,
            "resource_type": resource.ResourceType,
        },
    )

    # A list of rules that apply to the resource type being evaluated.
    matching_rules = []

    for rule in rules:
        extras = {
            "action": "find_matching_rules",
            "account_id": resource.AccountId,
            "accounts": account is not None,
            "resource_id": resource.ResourceId,
            "resource_type": resource.ResourceType,
            "rule.account_ids": rule.AccountIds,
            "rule.enabled": rule.Enabled,
            "rule.organizational_paths": rule.OrganizationalPaths,
            "rule.resource_type": rule.ResourceType,
            "rule.ruleId": rule.RuleId,
        }
        if account is not None:
            extras.update(
                {
                    "account.name": account.AccountName,
                    "account.ou_path": account.OUPath,
                    "account.status": account.Status,
                }
            )

        logger.debug(
            "Checking rule against resource",
            extra=extras,
        )

        # First we check if the rule is enabled, if not we skip it.
        if not rule.Enabled:
            continue

        # Next we check if the rule matches the account or wildcard, if not we skip it.
        if (
            len(rule.AccountIds) > 0
            and rule.AccountIds != ["*"]
            and resource.AccountId not in rule.AccountIds
        ):
            continue

        # Next check the organizational paths if defined, if the resource's account is
        # not within any of the organizational paths, we skip it.
        if (
            account is not None
            and rule.has_organizational_paths()
            and not rule.is_inside_organizational_path(account.OUPath)
        ):
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

        logger.debug(
            "Adding matching rule for resource",
            extra={
                "action": "find_matching_rules",
                "account_id": resource.AccountId,
                "resource_id": resource.ResourceId,
                "resource_type": resource.ResourceType,
                "rule.ruleId": rule.RuleId,
            },
        )

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
        rules: A list of Rule objects representing the tagging rules to check against.
        resource: A Resource object representing the AWS resource being evaluated.

    Returns:
        A list of RuleEvaluation objects representing the evaluation of each rule against the resource,
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
        if not resource.contains_tag(tag) and rule.Required:
            conditions.add_non_compliant(
                annotation=f"Required tag '{tag}' missing",
                rule=rule,
            )

        # If the tag is present, check if it matches the permitted values if defined,
        # and check if it matches the value pattern if defined.
        if resource.contains_tag(tag):
            if rule.has_values() and not resource.is_value(tag, rule.Values):
                conditions.add_non_compliant(
                    annotation=f"Tag '{tag}' doesn't match permitted values: {rule.Values}",
                    rule=rule,
                    value=resource.Tags[tag],
                )

            if rule.has_value_pattern() and not resource.is_value_pattern(
                tag, rule.ValuePattern
            ):
                conditions.add_non_compliant(
                    annotation=f"Tag '{tag}' doesn't match the required pattern: {rule.ValuePattern}",
                    rule=rule,
                    value=resource.Tags[tag],
                )
        elif not rule.Required and not resource.contains_tag(tag):
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
    # Get the account metadata, which includes organizational unit paths, from the DynamoDB table.
    accounts_table_arn = event.get("accounts_table_arn") or os.environ.get(
        "TABLE_ARN_ORGANIZATIONS", None
    )
    # Get the result token from the event, which is used to report compliance results back to AWS Config.
    token = event["resultToken"]
    # Indicates the accounts metadata is enabled
    enable_accounts_metadata = accounts_table_arn is not None

    # Enable the rules caching from environment variable
    enable_cache = os.environ.get("RULES_CACHE_ENABLED", "false").lower() == "true"
    # Check if the event has an override to the cache setting
    if "enable_cache" in event:
        # Apply the override from the event if any
        enable_cache = event["enable_cache"].lower() == "true"
    # Get the cache TTL from environment variable or default to 3600 seconds (1 hour)
    cache_ttl_seconds = int(os.environ.get("RULES_CACHE_TTL_SECONDS", "3600"))

    logger.info(
        "Processing AWS Config event",
        extra={
            "action": "lambda_handler",
            "account_id": account_id,
            "accounts_table_arn": accounts_table_arn,
            "cache_ttl_seconds": cache_ttl_seconds,
            "enable_cache": enable_cache,
        },
    )

    # Extract relevant information from the event
    invoking_event = json.loads(event.get("invokingEvent", "{}"))
    # The configuration item contains details about the resource being evaluated.
    configuration_item = invoking_event.get("configurationItem", {})
    # Parse the configuration item into a Resource dict for easier handling.
    resource = Resource.parse(configuration_item)
    # Is a list of evaluations for each rule that applies to this resource,
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
                "account_id": resource.AccountId,
                "resource_id": resource.ResourceId,
            },
        )
        # We have nothing to evaluate, so we return NOT_APPLICABLE for this resource and exit early.
        evaluations.add_not_applicable(
            annotation="Resource has been deleted, ignoring tagging compliance."
        )

    else:
        # We default to non account information
        account = None
        # Retrieve the rules from the DynamoDB table
        rules = get_rules(
            enable_cache=enable_cache,
            table_arn=table_arn,
            ttl_seconds=cache_ttl_seconds,
        )
        # Retrieve the account metadata if needed
        if enable_accounts_metadata:
            account = get_account(
                account_id=account_id,
                table_arn=accounts_table_arn,
                enable_cache=enable_cache,
                ttl_seconds=21600,  # Cache account metadata for 6 hours by default
            )
        else:
            logger.debug(
                "Accounts metadata is disabled, skipping retrieval of account organizational data",
                extra={
                    "action": "lambda_handler",
                    "account_id": account_id,
                },
            )

        # Find matching compliance rules for
        matching_rules = find_matching_rules(
            rules=rules,
            resource=resource,
            account=account,
        )
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
        reasons = "; ".join(evaluations.get_non_compliance_reasons())
        # If the annotation exceeds 256 characters, we truncate it to fit within AWS
        # Config limits, ensuring we don't cut off in the middle of a reason.
        if len(reasons) > 200:
            truncated_reasons = reasons[:197] + "..."
            annotation = f"Resource is non-compliant. Reasons: {truncated_reasons}"
        else:
            annotation = f"Resource is non-compliant. Reasons: {reasons}"

        compliance_type = COMPLIANCE_TYPE_NON_COMPLIANT

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
