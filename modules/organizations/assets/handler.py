"""
Lambda handler for AWS Organizations account inventory synchronization.

This function is invoked periodically to synchronize AWS account information
from AWS Organizations to a DynamoDB table, including organizational paths,
account names, IDs, and status.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List

import boto3

# Boto3 clients for AWS Organizations and DynamoDB
organizations_client = boto3.client("organizations")
# DynamoDB client is used to store account information in a DynamoDB table
dynamodb_client = boto3.client("dynamodb")


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
    # The timestamp when this record was last updated
    LastUpdated: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )


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


def store_accounts_in_dynamodb(
    accounts: List[AccountInfo],
    table_arn: str,
) -> int:
    """
    Store account information in DynamoDB table.

    Args:
        accounts: A list of AccountInfo objects to store
        table_name: The name of the DynamoDB table

    Returns:
        The number of accounts successfully stored
    """

    stored_count = 0
    logger.info(
        "Storing accounts in DynamoDB",
        extra={
            "action": "store_accounts_in_dynamodb",
            "table_arn": table_arn,
            "account_count": len(accounts),
        },
    )

    # Extract the table name from the ARN (assuming format: arn:aws:dynamodb:region:account-id:table/table-name)
    table_name = table_arn.split("/")[-1]  # Extract table name from ARN for logging

    try:
        for account in accounts:
            try:
                dynamodb_client.put_item(
                    TableName=table_name,
                    Item={
                        "AccountId": {"S": account.AccountId},
                        "AccountName": {"S": account.AccountName},
                        "OUPath": {"S": account.OUPath},
                        "Status": {"S": account.Status},
                        "LastUpdated": {"S": account.LastUpdated},
                    },
                )
                stored_count += 1

                logger.debug(
                    "Stored account information in DynamoDB",
                    extra={
                        "action": "store_accounts_in_dynamodb",
                        "account_id": account.AccountId,
                        "table_name": table_name,
                    },
                )
            except Exception as item_error:
                logger.error(
                    "Failed to store account in DynamoDB",
                    extra={
                        "action": "store_accounts_in_dynamodb",
                        "account_id": account.AccountId,
                        "error": str(item_error),
                    },
                )

        logger.info(
            "Stored accounts in DynamoDB",
            extra={
                "action": "store_accounts_in_dynamodb",
                "table_name": table_name,
                "stored_count": stored_count,
                "total_count": len(accounts),
            },
        )
    except Exception as e:
        logger.error(
            "Failed to store accounts in DynamoDB",
            extra={
                "action": "store_accounts_in_dynamodb",
                "table_name": table_name,
                "error": str(e),
            },
        )
        raise

    return stored_count


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
    AWS Lambda handler for syncing AWS Organizations account information to DynamoDB.

    Args:
        event: The Lambda event payload (not used in this function)
        context: The Lambda execution context

    Returns:
        A dictionary containing the execution results with stored_count and status
    """

    logger.info(
        "Starting AWS Organizations account inventory sync",
        extra={
            "action": "lambda_handler",
            "request_id": context.aws_request_id if context else None,
        },
    )

    try:
        # Check for required environment variables and get the DynamoDB table ARN
        table_arn = os.environ.get("DYNAMODB_TABLE_ARN")
        if not table_arn:
            logger.error(
                "Missing required environment variable",
                extra={"var_name": "DYNAMODB_TABLE_ARN"},
            )
            raise ValueError(
                "Environment variable DYNAMODB_TABLE_ARN is required but not set."
            )

        # Retrieve all accounts with their details
        accounts = list_accounts_with_details(build_ou_map())
        # Store the accounts in DynamoDB
        stored_count = store_accounts_in_dynamodb(
            accounts=accounts,
            table_arn=table_arn,
        )

        result = {
            "statusCode": 200,
            "body": {
                "message": "Successfully synced AWS Organizations accounts",
                "stored_count": stored_count,
                "total_count": len(accounts),
            },
        }

        logger.info(
            "Completed AWS Organizations account inventory sync",
            extra={
                "action": "lambda_handler",
                "stored_count": stored_count,
                "total_count": len(accounts),
            },
        )

        return result

    except Exception as e:
        logger.error(
            "Failed to sync AWS Organizations accounts",
            extra={
                "action": "lambda_handler",
                "error": str(e),
            },
        )

        return {
            "statusCode": 500,
            "body": {
                "message": "Failed to sync AWS Organizations accounts",
                "error": str(e),
            },
        }
