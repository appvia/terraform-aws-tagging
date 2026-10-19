"""S3 store for policy, mappings, and inventory with caching."""

import io
import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import boto3
import yaml
from botocore.exceptions import ClientError

from engine import Account
from policy import load_policy_text

# Module-level S3 client
s3_client = boto3.client("s3")

# Module-level cache: key -> (etag, fetched_at, parsed_object)
# Cache key format: f"{bucket}/{key}"
_cache = {}

# ETag sentinel marking a cached NoSuchKey for the inventory (negative cache)
_MISSING = object()

# Cache configuration
_cache_config = {"enabled": True, "ttl_seconds": 300}

logger = logging.getLogger(__name__)


class MappingsError(Exception):
    """The mappings file is unreadable or invalid."""


class InventoryError(Exception):
    """The inventory file is unreadable or invalid."""


@dataclass(frozen=True)
class Mappings:
    to_config: Dict[str, str]  # aws_s3_bucket -> AWS::S3::Bucket
    to_terraform: Dict[str, Tuple[str, ...]]  # AWS::S3::Bucket -> (aws_s3_bucket, ...)

    def taggable(self, config_type: str) -> bool:
        """Return True if config_type is taggable (appears in mappings values)."""
        return config_type in self.to_terraform


def configure_cache(enabled: bool, ttl_seconds: int) -> None:
    """Configure cache behavior."""
    global _cache_config
    _cache_config = {"enabled": enabled, "ttl_seconds": ttl_seconds}
    logger.debug(
        "Cache configured",
        extra={
            "action": "configure_cache",
            "enabled": enabled,
            "ttl_seconds": ttl_seconds,
        },
    )


def parse_mappings(text: str) -> Mappings:
    """
    Parse mappings YAML text and return a Mappings object.

    Validates:
    - version: 1
    - mappings is a dict
    - All keys are non-empty strings
    - All values are strings starting with 'AWS::'

    Builds a reverse mapping (to_terraform) where multiple Terraform types
    can map to the same Config type. The reverse mapping values are tuples
    sorted alphabetically.

    Raises MappingsError if validation fails.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise MappingsError(f"cannot parse mappings: {err}") from err

    if not isinstance(data, dict):
        raise MappingsError("mappings must be a mapping")

    version = data.get("version")
    if version != 1:
        raise MappingsError(f"unsupported mappings version {version!r}, expected 1")

    mappings_dict = data.get("mappings")
    if mappings_dict is None:
        raise MappingsError("mappings must have a 'mappings' key")

    if not isinstance(mappings_dict, dict):
        raise MappingsError("mappings must be a mapping")

    # Validate each mapping
    to_config = {}
    to_terraform = {}

    for tf_type, config_type in mappings_dict.items():
        # Validate key is a non-empty string
        if not isinstance(tf_type, str) or not tf_type:
            raise MappingsError(
                f"mapping key must be a non-empty string, got {tf_type!r}"
            )

        # Validate value is a string starting with AWS::
        if not isinstance(config_type, str):
            raise MappingsError(
                f"mapping value for {tf_type!r} must be a string, got {type(config_type).__name__}"
            )

        if not config_type.startswith("AWS::"):
            raise MappingsError(
                f"mapping value for {tf_type!r} must start with 'AWS::', got {config_type!r}"
            )

        to_config[tf_type] = config_type

        # Build reverse mapping
        if config_type not in to_terraform:
            to_terraform[config_type] = []
        to_terraform[config_type].append(tf_type)

    # Convert reverse mapping lists to sorted tuples
    to_terraform = {k: tuple(sorted(v)) for k, v in to_terraform.items()}

    return Mappings(to_config=to_config, to_terraform=to_terraform)


def parse_inventory(text: str) -> Dict[str, Account]:
    """
    Parse inventory YAML text and return a dict of account_id -> Account.

    Validates:
    - version: 1
    - accounts is a dict
    - Each account has name, ou_path, status (strings)
    - tags is optional, defaults to {}
    - Account IDs can be int or str, coerced to str

    Raises InventoryError if validation fails.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise InventoryError(f"cannot parse inventory: {err}") from err

    if not isinstance(data, dict):
        raise InventoryError("inventory must be a mapping")

    version = data.get("version")
    if version != 1:
        raise InventoryError(f"unsupported inventory version {version!r}, expected 1")

    accounts_dict = data.get("accounts")
    if accounts_dict is None:
        raise InventoryError("inventory must have an 'accounts' key")

    if not isinstance(accounts_dict, dict):
        raise InventoryError("accounts must be a mapping")

    result = {}

    for account_id, account_data in accounts_dict.items():
        # Coerce account_id to string (YAML may load unquoted numeric IDs as int)
        # Note: zero-padding loss is a risk, so fixtures and Task 6 should quote them
        account_id_str = str(account_id)

        if not isinstance(account_data, dict):
            raise InventoryError(f"account {account_id_str} data must be a mapping")

        # Extract required fields
        name = account_data.get("name")
        ou_path = account_data.get("ou_path")
        status = account_data.get("status")
        tags = account_data.get("tags", {})

        # Validate required fields
        if not isinstance(name, str):
            raise InventoryError(f"account {account_id_str} missing or invalid 'name'")
        if not isinstance(ou_path, str):
            raise InventoryError(
                f"account {account_id_str} missing or invalid 'ou_path'"
            )
        if not isinstance(status, str):
            raise InventoryError(
                f"account {account_id_str} missing or invalid 'status'"
            )

        # Validate tags
        if not isinstance(tags, dict):
            raise InventoryError(f"account {account_id_str} 'tags' must be a mapping")

        # Convert tags to str->str mapping
        tags_dict = {str(k): str(v) for k, v in tags.items()}

        result[account_id_str] = Account(
            account_id=account_id_str,
            name=name,
            ou_path=ou_path,
            status=status,
            tags=tags_dict,
        )

    return result


def _fetch_from_s3(
    bucket: str, key: str, if_none_match: Optional[str] = None
) -> Tuple[str, str]:
    """
    Fetch an object from S3.

    Returns: (body_text, etag)

    Raises:
    - ClientError with code '304' or 'NotModified' if ETag matches
    - ClientError for other S3 errors
    """
    params = {"Bucket": bucket, "Key": key}
    if if_none_match:
        params["IfNoneMatch"] = if_none_match

    try:
        response = s3_client.get_object(**params)
        body = response["Body"].read()
        etag = response.get("ETag", "")
        return body.decode("utf-8"), etag
    except ClientError as err:
        # Handle 304 Not Modified
        error_code = err.response.get("Error", {}).get("Code", "")
        status_code = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)

        if error_code in ("304", "NotModified") or status_code == 304:
            # Re-raise as a specific error so caller can detect
            raise

        # Re-raise other errors
        raise


def _load_with_cache(bucket: str, key: str, parser_func, error_type, object_type: str):
    """
    Generic loader with caching logic.

    Args:
        bucket: S3 bucket name
        key: S3 object key
        parser_func: Function to parse text -> parsed_object
        error_type: Exception type for errors (e.g., PolicyError)
        object_type: String describing the object type for logging (e.g., "policy")

    Returns:
        Parsed object from parser_func

    Cache semantics:
    - When caching disabled: fetch unconditionally (no IfNoneMatch)
    - When enabled and within TTL: return cached copy
    - After TTL: revalidate with IfNoneMatch=etag
      - 304 (NotModified): refresh fetched_at and return cached parse
      - Other error with cached copy: log warning, return stale copy
      - No cached copy: raise
    """
    cache_key = f"{bucket}/{key}"
    now = time.time()

    # Check if caching is enabled
    if not _cache_config["enabled"]:
        # Caching disabled: always fetch
        logger.debug(
            f"Fetching {object_type} (caching disabled)",
            extra={"action": f"load_{object_type}", "bucket": bucket, "key": key},
        )
        body, etag = _fetch_from_s3(bucket, key)
        return parser_func(body)

    # Check cache
    cached = _cache.get(cache_key)
    ttl = _cache_config["ttl_seconds"]

    if cached:
        etag, fetched_at, parsed = cached
        age = now - fetched_at

        if age < ttl:
            # Cache hit within TTL
            logger.debug(
                f"Serving {object_type} from cache",
                extra={
                    "action": f"load_{object_type}",
                    "bucket": bucket,
                    "key": key,
                    "age": age,
                },
            )
            return parsed

        # TTL expired: revalidate
        logger.debug(
            f"Revalidating {object_type} (TTL expired)",
            extra={
                "action": f"load_{object_type}",
                "bucket": bucket,
                "key": key,
                "age": age,
            },
        )

        try:
            body, new_etag = _fetch_from_s3(bucket, key, if_none_match=etag)
            # Fresh content
            parsed = parser_func(body)
            _cache[cache_key] = (new_etag, now, parsed)
            logger.debug(
                f"Fetched fresh {object_type}",
                extra={"action": f"load_{object_type}", "bucket": bucket, "key": key},
            )
            return parsed

        except ClientError as err:
            error_code = err.response.get("Error", {}).get("Code", "")
            status_code = err.response.get("ResponseMetadata", {}).get(
                "HTTPStatusCode", 0
            )

            # Handle 304 Not Modified
            if error_code in ("304", "NotModified") or status_code == 304:
                # Content unchanged, refresh timestamp
                _cache[cache_key] = (etag, now, parsed)
                logger.debug(
                    f"Serving {object_type} from cache (304 Not Modified)",
                    extra={
                        "action": f"load_{object_type}",
                        "bucket": bucket,
                        "key": key,
                    },
                )
                return parsed

            # Other error: serve stale if we have it
            logger.warning(
                f"Error revalidating {object_type}, serving stale cached copy",
                extra={
                    "action": f"load_{object_type}",
                    "bucket": bucket,
                    "key": key,
                    "error": str(err),
                },
            )
            return parsed

    # No cached copy: fetch fresh
    logger.debug(
        f"Fetching {object_type} (cold start)",
        extra={"action": f"load_{object_type}", "bucket": bucket, "key": key},
    )
    body, etag = _fetch_from_s3(bucket, key)
    parsed = parser_func(body)
    _cache[cache_key] = (etag, now, parsed)
    return parsed


def load_policy(bucket: str, key: str):
    """
    Load and parse policy from S3 with caching.

    Returns: Policy object

    Raises:
    - PolicyError if the policy is invalid
    - ClientError if S3 fetch fails (and no cached copy available)
    """
    from policy import PolicyError

    return _load_with_cache(bucket, key, load_policy_text, PolicyError, "policy")


def load_mappings(bucket: str, key: str) -> Mappings:
    """
    Load and parse mappings from S3 with caching.

    Returns: Mappings object

    Raises:
    - MappingsError if the mappings file is invalid
    - ClientError if S3 fetch fails (and no cached copy available)
    """
    return _load_with_cache(bucket, key, parse_mappings, MappingsError, "mappings")


def load_inventory(bucket: str, key: Optional[str]) -> Optional[Dict[str, Account]]:
    """
    Load and parse inventory from S3 with caching.

    Returns:
    - Dict[str, Account] if inventory exists
    - None if key is empty/None or object doesn't exist (NoSuchKey)

    Raises:
    - InventoryError if the inventory file is invalid
    - ClientError if S3 fetch fails with error other than NoSuchKey (and no cached copy)
    """
    # Handle empty key
    if not key:
        logger.debug(
            "Inventory key is empty, returning None",
            extra={"action": "load_inventory", "bucket": bucket},
        )
        return None

    # A cached NoSuchKey (negative cache entry) is served for the TTL, so an
    # absent inventory does not cost a GET on every event
    cache_key = f"{bucket}/{key}"
    cached = _cache.get(cache_key)
    if _cache_config["enabled"] and cached and cached[0] is _MISSING:
        if time.time() - cached[1] < _cache_config["ttl_seconds"]:
            return None
        del _cache[cache_key]

    # Try to load with cache
    try:
        return _load_with_cache(
            bucket, key, parse_inventory, InventoryError, "inventory"
        )
    except ClientError as err:
        error_code = err.response.get("Error", {}).get("Code", "")

        # Handle NoSuchKey as None (inventory not configured)
        if error_code == "NoSuchKey":
            logger.debug(
                "Inventory object does not exist (NoSuchKey), returning None",
                extra={"action": "load_inventory", "bucket": bucket, "key": key},
            )
            if _cache_config["enabled"]:
                _cache[cache_key] = (_MISSING, time.time(), None)
            return None

        # Re-raise other errors
        raise
