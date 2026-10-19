"""
Lambda handler for AWS Organizations account inventory synchronization.

This function is invoked on a schedule and on Organizations account events
(create, close, move, tag, untag) to write the account inventory -- account
names, organizational paths, status and account tags -- to a single YAML
object (accounts.yaml) in the policy bucket. The object is only rewritten when
its content changes. When a conformance pack name is configured, the
organization conformance pack is reconciled on every run: it is re-put
whenever its InventoryVersion differs from the inventory's content sha256, so
AWS Config re-evaluates every account against the new inventory.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import yaml

# Boto3 client for AWS Organizations, used to list OUs, accounts and account tags
organizations_client = boto3.client("organizations")
# S3 client is used to store the account inventory in the policy bucket
s3_client = boto3.client("s3")
# Config client is used to re-put the organization conformance pack on change
config_client = boto3.client("config")

# The version of the inventory format (parsed by the validation lambda)
INVENTORY_VERSION = 1
# The name of the conformance pack parameter carrying the inventory hash
INVENTORY_PARAMETER = "InventoryVersion"
# S3 error codes indicating the inventory object does not exist yet
NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound"}


@dataclass
class AccountInfo:
    """Represents account information from AWS Organizations."""

    # The AWS account ID
    AccountId: str
    # The name of the account
    AccountName: str
    # The organizational unit path (e.g., "root/engineering/platform")
    OUPath: str
    # The account status (e.g., ACTIVE, SUSPENDED)
    Status: str
    # The tags applied to the account in AWS Organizations
    Tags: Dict[str, str] = field(default_factory=dict)


def content_sha256(body: str) -> str:
    """Return the hex sha256 of the inventory body (the InventoryVersion)."""

    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def list_account_tags(account_id: str) -> Dict[str, str]:
    """
    Retrieve the tags applied to an account in AWS Organizations.

    Args:
        account_id: The AWS account ID

    Returns:
        A dictionary of tag keys to values, merged across all pages
    """

    tags: Dict[str, str] = {}
    paginator = organizations_client.get_paginator("list_tags_for_resource")
    for page in paginator.paginate(ResourceId=account_id):
        for tag in page.get("Tags", []):
            tags[tag["Key"]] = tag["Value"]

    return tags


def parse_ou_path(ou_id: str, ou_map: Dict[str, Dict[str, Any]]) -> str:
    """
    Build the organizational unit path for an account.

    Args:
        ou_id: The organizational unit ID to start from
        ou_map: A map of OU IDs to their details (name, parent_id)

    Returns:
        The full path from root to the OU (e.g., "root/engineering/platform")
    """

    path_parts = []
    current_id = ou_id

    # Walk up the hierarchy from the OU to the root
    while current_id in ou_map:
        ou_info = ou_map[current_id]
        path_parts.append(ou_info["name"])
        current_id = ou_info.get("parent_id")
        if current_id is None:
            break

    # Reverse to get root-to-leaf order
    path_parts.reverse()

    return "/".join(path_parts) if path_parts else "root"


def build_ou_map() -> Dict[str, Dict[str, Any]]:
    """
    Build a map of organizational units with their hierarchy information.

    Returns:
        A dictionary mapping OU IDs to their details (name, parent_id)
    """

    ou_map = {}
    logger.info(
        "Building organizational unit hierarchy",
        extra={"action": "build_ou_map"},
    )

    try:
        # Get the root OU
        root_response = organizations_client.list_roots()
        root_id = root_response["Roots"][0]["Id"]
        ou_map[root_id] = {"name": "root", "parent_id": None}

        # Recursively get all OUs
        paginator = organizations_client.get_paginator(
            "list_organizational_units_for_parent"
        )

        def process_ou(parent_id: str) -> None:
            """Recursively process OUs and their children."""
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get("OrganizationalUnits", []):
                    ou_id = ou["Id"]
                    ou_map[ou_id] = {
                        "name": ou["Name"],
                        "parent_id": parent_id,
                    }
                    # Recursively process children
                    process_ou(ou_id)

        process_ou(root_id)
        logger.info(
            "Built organizational unit hierarchy",
            extra={
                "action": "build_ou_map",
                "ou_count": len(ou_map),
            },
        )
    except Exception as e:
        logger.error(
            "Failed to build organizational unit hierarchy",
            extra={
                "action": "build_ou_map",
                "error": str(e),
            },
        )
        raise

    return ou_map


def list_accounts_with_details(ou_map: Dict[str, Dict[str, Any]]) -> List[AccountInfo]:
    """
    List all accounts in the organization with their details.

    Args:
        ou_map: A map of OU IDs to their hierarchy information

    Returns:
        A list of AccountInfo objects containing account details
    """

    accounts = []
    logger.info(
        "Retrieving accounts from AWS Organizations",
        extra={"action": "list_accounts_with_details"},
    )

    try:
        paginator = organizations_client.get_paginator("list_accounts")

        for page in paginator.paginate():
            for account in page.get("Accounts", []):
                account_id = account["Id"]
                account_name = account["Name"]
                status = account["Status"]

                # Get the organizational unit for this account
                parent_response = organizations_client.list_parents(ChildId=account_id)
                parent_id = (
                    parent_response["Parents"][0]["Id"]
                    if parent_response["Parents"]
                    else None
                )
                ou_path = parse_ou_path(parent_id, ou_map) if parent_id else "root"

                account_info = AccountInfo(
                    AccountId=account_id,
                    AccountName=account_name,
                    OUPath=ou_path,
                    Status=status,
                    Tags=list_account_tags(account_id),
                )
                accounts.append(account_info)

                logger.debug(
                    "Retrieved account information",
                    extra={
                        "action": "list_accounts_with_details",
                        "account_id": account_id,
                        "account_name": account_name,
                        "ou_path": ou_path,
                        "status": status,
                        "tag_count": len(account_info.Tags),
                    },
                )

        logger.info(
            "Retrieved accounts from AWS Organizations",
            extra={
                "action": "list_accounts_with_details",
                "account_count": len(accounts),
            },
        )
    except Exception as e:
        logger.error(
            "Failed to retrieve accounts from AWS Organizations",
            extra={
                "action": "list_accounts_with_details",
                "error": str(e),
            },
        )
        raise

    return accounts


class _AccountId(str):
    """An account ID, always emitted as a quoted YAML string."""


class _InventoryDumper(yaml.SafeDumper):
    """A safe dumper that quotes account IDs so no YAML parser reads them as integers."""


_InventoryDumper.add_representer(
    _AccountId,
    lambda dumper, value: dumper.represent_scalar(
        "tag:yaml.org,2002:str", str(value), style="'"
    ),
)


def render_inventory(accounts: List[AccountInfo]) -> str:
    """
    Render the account inventory as deterministic YAML.

    The output is keyed by account ID (sorted, always quoted strings), with
    sorted keys and no timestamps, so the same organization always renders to
    the same bytes and its sha256 only changes when the inventory does.

    Args:
        accounts: A list of AccountInfo objects to render

    Returns:
        The YAML document (version: 1) parsed by the validation lambda
    """

    document = {
        "version": INVENTORY_VERSION,
        "accounts": {
            _AccountId(account.AccountId): {
                "name": account.AccountName,
                "ou_path": account.OUPath,
                "status": account.Status,
                "tags": {str(k): str(v) for k, v in account.Tags.items()},
            }
            for account in sorted(accounts, key=lambda a: str(a.AccountId))
        },
    }

    return yaml.dump(
        document,
        Dumper=_InventoryDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=True,
    )


def store_inventory(bucket: str, key: str, body: str) -> bool:
    """
    Write the inventory to S3 when its content has changed.

    The content sha256 is stored in the object metadata (content-sha256) and
    compared with the current object's metadata before writing, so unchanged
    inventories do not create new object versions.

    Args:
        bucket: The name of the policy bucket
        key: The object key of the inventory
        body: The rendered inventory YAML

    Returns:
        True if the object was written, False if the content was unchanged
    """

    digest = content_sha256(body)

    try:
        head = s3_client.head_object(Bucket=bucket, Key=key)
        current = head.get("Metadata", {}).get("content-sha256")
        if current == digest:
            logger.info(
                "Account inventory unchanged, skipping write",
                extra={
                    "action": "store_inventory",
                    "bucket": bucket,
                    "key": key,
                    "content_sha256": digest,
                },
            )
            return False
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") not in NOT_FOUND_CODES:
            logger.error(
                "Failed to read the current account inventory",
                extra={
                    "action": "store_inventory",
                    "bucket": bucket,
                    "key": key,
                    "error": str(e),
                },
            )
            raise
        logger.info(
            "Account inventory does not exist yet, creating it",
            extra={"action": "store_inventory", "bucket": bucket, "key": key},
        )

    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="application/x-yaml",
        Metadata={
            "content-sha256": digest,
            "generated-at": datetime.now(tz=timezone.utc).isoformat(),
        },
    )
    logger.info(
        "Stored account inventory",
        extra={
            "action": "store_inventory",
            "bucket": bucket,
            "key": key,
            "content_sha256": digest,
        },
    )

    return True


def bump_conformance_pack(name: str, version: str, template_uri: str) -> bool:
    """
    Reconcile the organization conformance pack's InventoryVersion.

    The pack is described on every call and re-put only when its current
    InventoryVersion differs from the given version, so a re-put that failed
    on an earlier run (after the inventory was written) is retried on the
    next run. Changing an input parameter makes AWS Config redeploy the pack
    and re-evaluate every in-scope resource in every member account. The
    existing input parameters, excluded accounts and delivery settings are
    preserved. DescribeOrganizationConformancePacks does not return the
    template location, so the template URI is supplied by the caller.

    Args:
        name: The name of the organization conformance pack
        version: The desired InventoryVersion (the inventory content sha256)
        template_uri: The S3 URI of the conformance pack template

    Returns:
        True if the pack was re-put, False if it was current or not found
    """

    try:
        response = config_client.describe_organization_conformance_packs(
            OrganizationConformancePackNames=[name]
        )
    except ClientError as e:
        if (
            e.response.get("Error", {}).get("Code")
            != "NoSuchOrganizationConformancePackException"
        ):
            raise
        response = {}

    packs = response.get("OrganizationConformancePacks", [])
    if not packs:
        logger.warning(
            "Organization conformance pack not found, skipping re-evaluation",
            extra={"action": "bump_conformance_pack", "conformance_pack": name},
        )
        return False
    pack = packs[0]

    current = next(
        (
            p.get("ParameterValue")
            for p in pack.get("ConformancePackInputParameters", [])
            if p.get("ParameterName") == INVENTORY_PARAMETER
        ),
        None,
    )
    if current == version:
        logger.info(
            "Organization conformance pack inventory version is current",
            extra={
                "action": "bump_conformance_pack",
                "conformance_pack": name,
                "inventory_version": version,
            },
        )
        return False

    parameters = [
        p
        for p in pack.get("ConformancePackInputParameters", [])
        if p.get("ParameterName") != INVENTORY_PARAMETER
    ]
    parameters.append({"ParameterName": INVENTORY_PARAMETER, "ParameterValue": version})

    request: Dict[str, Any] = {
        "OrganizationConformancePackName": name,
        "TemplateS3Uri": template_uri,
        "ConformancePackInputParameters": parameters,
        "ExcludedAccounts": pack.get("ExcludedAccounts", []),
    }
    for setting in ("DeliveryS3Bucket", "DeliveryS3KeyPrefix"):
        if pack.get(setting):
            request[setting] = pack[setting]

    config_client.put_organization_conformance_pack(**request)
    logger.info(
        "Re-put organization conformance pack with new inventory version",
        extra={
            "action": "bump_conformance_pack",
            "conformance_pack": name,
            "previous_inventory_version": current,
            "inventory_version": version,
        },
    )

    return True


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

        # Include extra fields from the record
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


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for syncing the AWS Organizations account inventory to S3.

    Args:
        event: The Lambda event payload (scheduled or CloudTrail event; not inspected)
        context: The Lambda execution context

    Returns:
        A dictionary with the status, the number of accounts and whether the
        inventory changed
    """

    logger.info(
        "Starting AWS Organizations account inventory sync",
        extra={
            "action": "lambda_handler",
            "request_id": context.aws_request_id if context else None,
        },
    )

    try:
        bucket = os.environ.get("BUCKET_NAME")
        if not bucket:
            logger.error(
                "Missing required environment variable",
                extra={"var_name": "BUCKET_NAME"},
            )
            raise ValueError(
                "Environment variable BUCKET_NAME is required but not set."
            )
        key = os.environ.get("ACCOUNTS_KEY") or "accounts.yaml"
        pack_name = os.environ.get("CONFORMANCE_PACK_NAME")
        template_uri = os.environ.get("CONFORMANCE_PACK_TEMPLATE_URI")

        # Retrieve all accounts with their details and render the inventory
        accounts = list_accounts_with_details(build_ou_map())
        body = render_inventory(accounts)
        # Only rewrite the inventory when the content changed
        changed = store_inventory(bucket, key, body)

        # Reconcile the pack on every run (not only on write), so a re-put that
        # failed after an earlier write is retried; it is a no-op when current
        if pack_name:
            if template_uri:
                bump_conformance_pack(pack_name, content_sha256(body), template_uri)
            else:
                logger.warning(
                    "Conformance pack name set without a template URI, skipping re-evaluation",
                    extra={
                        "action": "lambda_handler",
                        "conformance_pack": pack_name,
                        "var_name": "CONFORMANCE_PACK_TEMPLATE_URI",
                    },
                )

        logger.info(
            "Completed AWS Organizations account inventory sync",
            extra={
                "action": "lambda_handler",
                "account_count": len(accounts),
                "changed": changed,
            },
        )

        return {"status": "ok", "account_count": len(accounts), "changed": changed}

    except Exception as e:
        logger.error(
            "Failed to sync AWS Organizations accounts",
            extra={
                "action": "lambda_handler",
                "error": str(e),
            },
        )
        raise
