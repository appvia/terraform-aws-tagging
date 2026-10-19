"""
Unit tests for the S3 store module.

Tests cover:
- Mappings parsing and validation
- Inventory parsing and validation
- S3 loading with caching
- ETag revalidation
- Error handling
"""

import io
import json
import logging
import time
from datetime import datetime, timezone
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import store
from engine import Account
from policy import PolicyError

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def s3_stubber():
    """Create a Stubber for the module-level s3_client."""
    with Stubber(store.s3_client) as stubber:
        yield stubber


@pytest.fixture(autouse=True)
def reset_cache():
    """Reset the cache before each test."""
    store._cache.clear()
    store._cache_config = {"enabled": True, "ttl_seconds": 300}


@pytest.fixture
def sample_mappings_yaml():
    """A sample mappings.yaml content."""
    return """version: 1
mappings:
  aws_s3_bucket: AWS::S3::Bucket
  aws_instance: AWS::EC2::Instance
  aws_ebs_volume: AWS::EC2::Volume
  aws_db_instance: AWS::RDS::DBInstance
  aws_dynamodb_table: AWS::DynamoDB::Table
"""


@pytest.fixture
def sample_policy_yaml():
    """A sample policy.yaml content."""
    return """version: 1
rules:
  - name: required-tags
    description: Test rule
    steps:
      - assert: {tag: Environment, present: true}
"""


@pytest.fixture
def sample_accounts_yaml():
    """A sample accounts.yaml content."""
    return """version: 1
accounts:
  "123456789012":
    name: prod
    ou_path: root/workloads/prod
    status: ACTIVE
    tags:
      CostCentre: "42"
      Environment: production
  "234567890123":
    name: dev
    ou_path: root/workloads/dev
    status: ACTIVE
    tags: {}
"""


# ============================================================================
# Tests for parse_mappings
# ============================================================================


class TestParseMappings:
    """Tests for the parse_mappings function."""

    def test_parse_mappings_builds_reverse_map(self):
        """Two Terraform types to one Config type → to_terraform tuple of both, sorted."""
        text = """version: 1
mappings:
  aws_lb: AWS::ElasticLoadBalancingV2::LoadBalancer
  aws_alb: AWS::ElasticLoadBalancingV2::LoadBalancer
  aws_s3_bucket: AWS::S3::Bucket
"""
        mappings = store.parse_mappings(text)

        assert mappings.to_config == {
            "aws_lb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "aws_alb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "aws_s3_bucket": "AWS::S3::Bucket",
        }

        # Verify reverse mapping has both types sorted
        assert mappings.to_terraform["AWS::ElasticLoadBalancingV2::LoadBalancer"] == (
            "aws_alb",
            "aws_lb",
        )
        assert mappings.to_terraform["AWS::S3::Bucket"] == ("aws_s3_bucket",)

    def test_parse_mappings_rejects_non_aws_value(self):
        """aws_x: s3bucket → MappingsError."""
        text = """version: 1
mappings:
  aws_x: s3bucket
"""
        with pytest.raises(store.MappingsError, match="must start with 'AWS::'"):
            store.parse_mappings(text)

    def test_parse_mappings_rejects_invalid_version(self):
        """Version other than 1 → MappingsError."""
        text = """version: 2
mappings:
  aws_s3_bucket: AWS::S3::Bucket
"""
        with pytest.raises(store.MappingsError, match="version"):
            store.parse_mappings(text)

    def test_parse_mappings_rejects_missing_mappings(self):
        """Missing mappings key → MappingsError."""
        text = """version: 1
"""
        with pytest.raises(store.MappingsError, match="mappings"):
            store.parse_mappings(text)

    def test_parse_mappings_rejects_empty_key(self):
        """Empty string key → MappingsError."""
        text = """version: 1
mappings:
  "": AWS::S3::Bucket
"""
        with pytest.raises(store.MappingsError, match="non-empty"):
            store.parse_mappings(text)


# ============================================================================
# Tests for parse_inventory
# ============================================================================


class TestParseInventory:
    """Tests for the parse_inventory function."""

    def test_parse_inventory_with_tags(self, sample_accounts_yaml):
        """Parse inventory with account tags."""
        accounts = store.parse_inventory(sample_accounts_yaml)

        assert len(accounts) == 2
        assert "123456789012" in accounts
        assert accounts["123456789012"].account_id == "123456789012"
        assert accounts["123456789012"].name == "prod"
        assert accounts["123456789012"].ou_path == "root/workloads/prod"
        assert accounts["123456789012"].status == "ACTIVE"
        assert accounts["123456789012"].tags == {
            "CostCentre": "42",
            "Environment": "production",
        }

    def test_parse_inventory_with_empty_tags(self, sample_accounts_yaml):
        """Parse inventory with empty tags (missing or {})."""
        accounts = store.parse_inventory(sample_accounts_yaml)

        assert accounts["234567890123"].tags == {}

    def test_parse_inventory_coerces_numeric_account_ids(self):
        """YAML unquoted account ID loaded as int → coerced to string."""
        text = """version: 1
accounts:
  123456789012:
    name: prod
    ou_path: root/workloads/prod
    status: ACTIVE
    tags: {}
"""
        accounts = store.parse_inventory(text)
        assert "123456789012" in accounts

    def test_parse_inventory_rejects_invalid_version(self):
        """Version other than 1 → InventoryError."""
        text = """version: 2
accounts: {}
"""
        with pytest.raises(store.InventoryError, match="version"):
            store.parse_inventory(text)

    def test_parse_inventory_rejects_missing_fields(self):
        """Missing required fields → InventoryError."""
        text = """version: 1
accounts:
  "123456789012":
    name: prod
    status: ACTIVE
"""
        with pytest.raises(store.InventoryError, match="ou_path"):
            store.parse_inventory(text)


# ============================================================================
# Tests for Mappings.taggable
# ============================================================================


class TestMappingsTaggable:
    """Tests for the Mappings.taggable method."""

    def test_taggable_returns_true_for_mapped_config_type(self):
        """Config type in mappings values → taggable returns True."""
        text = """version: 1
mappings:
  aws_s3_bucket: AWS::S3::Bucket
"""
        mappings = store.parse_mappings(text)
        assert mappings.taggable("AWS::S3::Bucket") is True

    def test_taggable_returns_false_for_unmapped_type(self):
        """Config type not in mappings → taggable returns False."""
        text = """version: 1
mappings:
  aws_s3_bucket: AWS::S3::Bucket
"""
        mappings = store.parse_mappings(text)
        assert mappings.taggable("AWS::Lambda::Function") is False


# ============================================================================
# Tests for default mappings coverage
# ============================================================================


class TestDefaultMappings:
    """Tests for the default mappings.yaml file."""

    def test_default_mappings_cover_example_policy(self):
        """Every Terraform type operand in testdata/tagging-policy.yaml is in mappings.yaml."""
        # Load the default mappings
        with open("modules/validation/assets/mappings.yaml", encoding="utf-8") as f:
            mappings = store.parse_mappings(f.read())

        # Load the example policy
        with open(
            "modules/validation/assets/testdata/tagging-policy.yaml", encoding="utf-8"
        ) as f:
            from policy import load_policy_text

            policy = load_policy_text(f.read())

        # Collect all Terraform type operands (operands not starting with AWS::)
        terraform_types = set()

        def collect_types(rule):
            for step in rule.steps:
                if step.condition.target == "type":
                    if isinstance(step.condition.operand, tuple):
                        for operand in step.condition.operand:
                            if not operand.startswith("AWS::"):
                                terraform_types.add(operand)
            for child in rule.children:
                collect_types(child)

        for rule in policy.rules:
            collect_types(rule)

        # Verify all Terraform types are mapped
        missing = terraform_types - set(mappings.to_config.keys())
        assert not missing, f"Terraform types not in mappings.yaml: {missing}"


# ============================================================================
# Tests for S3 loading with caching
# ============================================================================


class TestLoadPolicy:
    """Tests for the load_policy function."""

    def test_load_policy_fetches_and_parses(self, s3_stubber, sample_policy_yaml):
        """Fetch policy from S3 and parse it."""
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_policy_yaml.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        policy = store.load_policy("test-bucket", "policy.yaml")

        assert len(policy.rules) == 1
        assert policy.rules[0].name == "required-tags"

    def test_invalid_policy_raises(self, s3_stubber):
        """S3 body version: 2 → PolicyError."""
        invalid_policy = """version: 2
rules: []
"""
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(invalid_policy.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        with pytest.raises(PolicyError, match="version"):
            store.load_policy("test-bucket", "policy.yaml")


class TestLoadMappings:
    """Tests for the load_mappings function."""

    def test_load_mappings_fetches_and_parses(self, s3_stubber, sample_mappings_yaml):
        """Fetch mappings from S3 and parse."""
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_mappings_yaml.encode("utf-8")),
                "ETag": '"def456"',
            },
            {"Bucket": "test-bucket", "Key": "mappings.yaml"},
        )

        mappings = store.load_mappings("test-bucket", "mappings.yaml")

        assert "aws_s3_bucket" in mappings.to_config
        assert mappings.to_config["aws_s3_bucket"] == "AWS::S3::Bucket"


class TestLoadInventory:
    """Tests for the load_inventory function."""

    def test_load_inventory_fetches_and_parses(self, s3_stubber, sample_accounts_yaml):
        """Fetch inventory from S3 and parse."""
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_accounts_yaml.encode("utf-8")),
                "ETag": '"ghi789"',
            },
            {"Bucket": "test-bucket", "Key": "accounts.yaml"},
        )

        accounts = store.load_inventory("test-bucket", "accounts.yaml")

        assert accounts is not None
        assert "123456789012" in accounts
        assert accounts["123456789012"].name == "prod"

    def test_inventory_missing_key_returns_none(self, s3_stubber):
        """NoSuchKey → None; empty key → None with no S3 call."""
        # Test empty key (no S3 call)
        result = store.load_inventory("test-bucket", "")
        assert result is None

        result = store.load_inventory("test-bucket", None)
        assert result is None

        # Test NoSuchKey error
        s3_stubber.add_client_error(
            "get_object",
            service_error_code="NoSuchKey",
            service_message="The specified key does not exist.",
            http_status_code=404,
        )

        result = store.load_inventory("test-bucket", "missing.yaml")
        assert result is None


# ============================================================================
# Tests for caching
# ============================================================================


class TestCaching:
    """Tests for cache behavior."""

    def test_cache_hit_within_ttl_makes_no_call(self, s3_stubber, sample_policy_yaml):
        """Cache hit within TTL → no S3 call."""
        store.configure_cache(enabled=True, ttl_seconds=300)

        # First call fetches from S3
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_policy_yaml.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        policy1 = store.load_policy("test-bucket", "policy.yaml")

        # Second call uses cache (no S3 call added to stubber)
        policy2 = store.load_policy("test-bucket", "policy.yaml")

        assert policy1 == policy2

    def test_revalidate_304_keeps_cached(self, s3_stubber, sample_policy_yaml):
        """After TTL, get_object(IfNoneMatch=etag) raising 304 returns the same object."""
        store.configure_cache(enabled=True, ttl_seconds=1)

        # First call fetches from S3
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_policy_yaml.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        policy1 = store.load_policy("test-bucket", "policy.yaml")

        # Wait for TTL to expire
        time.sleep(1.1)

        # Second call after TTL - revalidate with 304 response
        s3_stubber.add_client_error(
            "get_object",
            service_error_code="304",
            service_message="Not Modified",
            http_status_code=304,
        )

        policy2 = store.load_policy("test-bucket", "policy.yaml")

        assert policy1 == policy2

    def test_revalidate_error_serves_stale(
        self, s3_stubber, sample_policy_yaml, caplog
    ):
        """After TTL, a 503 → cached object returned, warning logged."""
        store.configure_cache(enabled=True, ttl_seconds=1)

        caplog.set_level(logging.WARNING)

        # First call fetches from S3
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_policy_yaml.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        policy1 = store.load_policy("test-bucket", "policy.yaml")

        # Wait for TTL to expire
        time.sleep(1.1)

        # Second call after TTL - revalidate fails with 503
        s3_stubber.add_client_error(
            "get_object",
            service_error_code="ServiceUnavailable",
            service_message="Service Unavailable",
            http_status_code=503,
        )

        policy2 = store.load_policy("test-bucket", "policy.yaml")

        # Should return stale cached copy
        assert policy1 == policy2

        # Should have logged a warning
        assert any("stale" in record.message.lower() for record in caplog.records)

    def test_cold_start_error_raises(self, s3_stubber):
        """No cached copy and 503 → raises."""
        store.configure_cache(enabled=True, ttl_seconds=300)

        s3_stubber.add_client_error(
            "get_object",
            service_error_code="ServiceUnavailable",
            service_message="Service Unavailable",
            http_status_code=503,
        )

        with pytest.raises(ClientError):
            store.load_policy("test-bucket", "policy.yaml")

    def test_caching_disabled_always_fetches(self, s3_stubber, sample_policy_yaml):
        """When caching disabled, every call fetches unconditionally (no IfNoneMatch)."""
        store.configure_cache(enabled=False, ttl_seconds=300)

        # First call
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_policy_yaml.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        store.load_policy("test-bucket", "policy.yaml")

        # Second call - should fetch again (not from cache)
        s3_stubber.add_response(
            "get_object",
            {
                "Body": io.BytesIO(sample_policy_yaml.encode("utf-8")),
                "ETag": '"abc123"',
            },
            {"Bucket": "test-bucket", "Key": "policy.yaml"},
        )

        store.load_policy("test-bucket", "policy.yaml")
