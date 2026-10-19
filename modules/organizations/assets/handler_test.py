"""
Unit tests for the AWS Organizations account inventory Lambda handler.

Tests cover:
- Organization unit hierarchy building
- Account tag retrieval (paginated)
- Account details retrieval
- Deterministic YAML inventory rendering
- Conditional S3 write of the inventory (content sha256)
- Re-putting the organization conformance pack with a new InventoryVersion
- Lambda handler integration
"""

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from botocore.exceptions import ClientError

import handler

## The shared inventory fixture parsed by the validation lambda (store.parse_inventory)
SHARED_FIXTURE = (
    Path(__file__).parent
    / ".."
    / ".."
    / "validation"
    / "assets"
    / "testdata"
    / "accounts.yaml"
)

TEMPLATE_URI = "s3://tagging-conformance-pack/conformance-packs/tagging-compliance.yaml"

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_account_info():
    """A sample AccountInfo object."""
    return handler.AccountInfo(
        AccountId="123456789012",
        AccountName="Production Account",
        OUPath="root/engineering/platform",
        Status="ACTIVE",
    )


@pytest.fixture
def fixture_accounts():
    """AccountInfo objects equivalent to the shared inventory fixture."""
    return [
        handler.AccountInfo(
            AccountId="234567890123",
            AccountName="dev",
            OUPath="root/workloads/dev",
            Status="ACTIVE",
            Tags={},
        ),
        handler.AccountInfo(
            AccountId="123456789012",
            AccountName="prod",
            OUPath="root/workloads/prod",
            Status="ACTIVE",
            Tags={"Environment": "production", "CostCentre": "42"},
        ),
    ]


@pytest.fixture
def sample_ou_map():
    """A sample organizational unit hierarchy map."""
    return {
        "r-1234": {"name": "root", "parent_id": None},
        "ou-1111": {"name": "engineering", "parent_id": "r-1234"},
        "ou-2222": {"name": "platform", "parent_id": "ou-1111"},
        "ou-3333": {"name": "finance", "parent_id": "r-1234"},
    }


@pytest.fixture
def mock_context():
    """Mock Lambda context object."""
    context = MagicMock()
    context.aws_request_id = "test-request-id-12345"
    return context


def _client_error(code, operation="HeadObject"):
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


# ============================================================================
# Tests for AccountInfo dataclass
# ============================================================================


class TestClients:
    """The AWS clients retry throttled calls (Organizations APIs throttle hard)."""

    @pytest.mark.parametrize(
        "client",
        [handler.organizations_client, handler.s3_client, handler.config_client],
    )
    def test_clients_use_adaptive_retries(self, client):
        # botocore normalises max_attempts=10 (retries) to 11 total attempts
        assert client.meta.config.retries == {
            "mode": "adaptive",
            "total_max_attempts": 11,
        }


class TestAccountInfo:
    """Tests for the AccountInfo dataclass."""

    def test_account_info_creation(self, sample_account_info):
        assert sample_account_info.AccountId == "123456789012"
        assert sample_account_info.AccountName == "Production Account"
        assert sample_account_info.OUPath == "root/engineering/platform"
        assert sample_account_info.Status == "ACTIVE"
        assert sample_account_info.Tags == {}

    def test_account_info_has_no_last_updated(self, sample_account_info):
        """The timestamp moved to the S3 object metadata (generated-at)."""
        assert not hasattr(sample_account_info, "LastUpdated")


# ============================================================================
# Tests for parse_ou_path function
# ============================================================================


class TestParseOUPath:
    """Tests for parse_ou_path function."""

    def test_parse_ou_path_deep_hierarchy(self, sample_ou_map):
        assert (
            handler.parse_ou_path("ou-2222", sample_ou_map)
            == "root/engineering/platform"
        )

    def test_parse_ou_path_single_level(self, sample_ou_map):
        assert handler.parse_ou_path("ou-1111", sample_ou_map) == "root/engineering"

    def test_parse_ou_path_root(self, sample_ou_map):
        assert handler.parse_ou_path("r-1234", sample_ou_map) == "root"

    def test_parse_ou_path_nonexistent_ou(self, sample_ou_map):
        assert handler.parse_ou_path("ou-nonexistent", sample_ou_map) == "root"

    def test_parse_ou_path_empty_map(self):
        assert handler.parse_ou_path("ou-1111", {}) == "root"


# ============================================================================
# Tests for build_ou_map function
# ============================================================================


class TestBuildOUMap:
    """Tests for build_ou_map function."""

    @patch("handler.organizations_client")
    def test_build_ou_map_success(self, mock_org_client):
        mock_org_client.list_roots.return_value = {
            "Roots": [{"Id": "r-1234", "Name": "root"}]
        }
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator

        def paginate_side_effect(ParentId):
            if ParentId == "r-1234":
                return iter(
                    [
                        {
                            "OrganizationalUnits": [
                                {"Id": "ou-1111", "Name": "engineering"},
                                {"Id": "ou-3333", "Name": "finance"},
                            ]
                        }
                    ]
                )
            if ParentId == "ou-1111":
                return iter(
                    [{"OrganizationalUnits": [{"Id": "ou-2222", "Name": "platform"}]}]
                )
            return iter([{"OrganizationalUnits": []}])

        mock_paginator.paginate.side_effect = paginate_side_effect

        ou_map = handler.build_ou_map()

        assert ou_map["r-1234"] == {"name": "root", "parent_id": None}
        assert ou_map["ou-2222"] == {"name": "platform", "parent_id": "ou-1111"}
        assert "ou-3333" in ou_map

    @patch("handler.organizations_client")
    def test_build_ou_map_organizations_error(self, mock_org_client):
        mock_org_client.list_roots.side_effect = Exception("API Error")

        with pytest.raises(Exception, match="API Error"):
            handler.build_ou_map()


# ============================================================================
# Tests for list_account_tags function
# ============================================================================


class TestListAccountTags:
    """Tests for list_account_tags function."""

    @patch("handler.organizations_client")
    def test_list_account_tags_paginates(self, mock_org_client):
        """Two pages of tags are merged into a single map."""
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = iter(
            [
                {"Tags": [{"Key": "Environment", "Value": "production"}]},
                {"Tags": [{"Key": "CostCentre", "Value": "42"}]},
            ]
        )

        tags = handler.list_account_tags("123456789012")

        assert tags == {"Environment": "production", "CostCentre": "42"}
        mock_org_client.get_paginator.assert_called_once_with("list_tags_for_resource")
        mock_paginator.paginate.assert_called_once_with(ResourceId="123456789012")

    @patch("handler.organizations_client")
    def test_list_account_tags_empty(self, mock_org_client):
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = iter([{"Tags": []}])

        assert handler.list_account_tags("123456789012") == {}


# ============================================================================
# Tests for list_accounts_with_details function
# ============================================================================


class TestListAccountsWithDetails:
    """Tests for list_accounts_with_details function."""

    @patch("handler.list_account_tags")
    @patch("handler.organizations_client")
    def test_list_accounts_with_details_success(
        self, mock_org_client, mock_tags, sample_ou_map
    ):
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "123456789012", "Name": "Production", "Status": "ACTIVE"},
                    {"Id": "210987654321", "Name": "Development", "Status": "ACTIVE"},
                ]
            }
        ]
        mock_org_client.list_parents.side_effect = [
            {"Parents": [{"Id": "ou-2222"}]},
            {"Parents": [{"Id": "ou-1111"}]},
        ]
        mock_tags.side_effect = [{"Environment": "production"}, {}]

        accounts = handler.list_accounts_with_details(sample_ou_map)

        assert len(accounts) == 2
        assert accounts[0].AccountId == "123456789012"
        assert accounts[0].OUPath == "root/engineering/platform"
        assert accounts[0].Tags == {"Environment": "production"}
        assert accounts[1].AccountName == "Development"
        assert accounts[1].OUPath == "root/engineering"
        assert accounts[1].Tags == {}

    @patch("handler.list_account_tags", return_value={})
    @patch("handler.organizations_client")
    def test_list_accounts_with_details_no_parent(
        self, mock_org_client, _mock_tags, sample_ou_map
    ):
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Accounts": [{"Id": "123456789012", "Name": "Orphan", "Status": "ACTIVE"}]}
        ]
        mock_org_client.list_parents.return_value = {"Parents": []}

        accounts = handler.list_accounts_with_details(sample_ou_map)

        assert accounts[0].OUPath == "root"

    @patch("handler.organizations_client")
    def test_list_accounts_with_details_organizations_error(
        self, mock_org_client, sample_ou_map
    ):
        mock_org_client.get_paginator.side_effect = Exception("API Error")

        with pytest.raises(Exception, match="API Error"):
            handler.list_accounts_with_details(sample_ou_map)


# ============================================================================
# Tests for render_inventory function
# ============================================================================


class TestRenderInventory:
    """Tests for render_inventory function."""

    def test_render_inventory_deterministic(self, fixture_accounts):
        """The same accounts in a different order render to an identical string."""
        first = handler.render_inventory(fixture_accounts)
        second = handler.render_inventory(list(reversed(fixture_accounts)))

        assert first == second
        data = yaml.safe_load(first)
        assert data["version"] == 1
        assert list(data["accounts"].keys()) == ["123456789012", "234567890123"]
        assert data["accounts"]["123456789012"] == {
            "name": "prod",
            "ou_path": "root/workloads/prod",
            "status": "ACTIVE",
            "tags": {"CostCentre": "42", "Environment": "production"},
        }

    def test_render_inventory_quotes_account_ids(self):
        """Account IDs (even with leading zeros) stay strings after a YAML round-trip."""
        body = handler.render_inventory(
            [
                handler.AccountInfo(
                    AccountId="012345678901",
                    AccountName="zero",
                    OUPath="root",
                    Status="ACTIVE",
                    Tags={"Count": "1", "Enabled": "yes"},
                )
            ]
        )
        data = yaml.safe_load(body)

        assert list(data["accounts"].keys()) == ["012345678901"]
        assert data["accounts"]["012345678901"]["tags"] == {
            "Count": "1",
            "Enabled": "yes",
        }

    def test_render_inventory_always_quotes_account_ids(self, fixture_accounts):
        """IDs are quoted even when PyYAML would not need it (YAML 1.2 parsers read 0123... as int)."""
        accounts = fixture_accounts + [
            handler.AccountInfo(
                AccountId="012345678901",
                AccountName="zero",
                OUPath="root",
                Status="ACTIVE",
            )
        ]
        body = handler.render_inventory(accounts)

        for account_id in ("012345678901", "123456789012", "234567890123"):
            assert f"'{account_id}':" in body

    def test_render_inventory_has_no_timestamps(self, fixture_accounts):
        body = handler.render_inventory(fixture_accounts)

        assert "generated" not in body
        assert "updated" not in body.lower()

    def test_render_inventory_matches_shared_fixture(self, fixture_accounts):
        """The output is equivalent to the fixture parsed by the validation lambda."""
        fixture = SHARED_FIXTURE.read_text()

        assert yaml.safe_load(
            handler.render_inventory(fixture_accounts)
        ) == yaml.safe_load(fixture)


# ============================================================================
# Tests for store_inventory function
# ============================================================================


class TestStoreInventory:
    """Tests for store_inventory function."""

    BODY = "version: 1\naccounts: {}\n"

    @patch("handler.s3_client")
    def test_store_inventory_skips_unchanged(self, mock_s3):
        digest = hashlib.sha256(self.BODY.encode("utf-8")).hexdigest()
        mock_s3.head_object.return_value = {"Metadata": {"content-sha256": digest}}

        assert handler.store_inventory("bucket", "accounts.yaml", self.BODY) is False
        mock_s3.head_object.assert_called_once_with(
            Bucket="bucket", Key="accounts.yaml"
        )
        mock_s3.put_object.assert_not_called()

    @patch("handler.s3_client")
    def test_store_inventory_writes_on_change(self, mock_s3):
        mock_s3.head_object.return_value = {"Metadata": {"content-sha256": "stale"}}

        assert handler.store_inventory("bucket", "accounts.yaml", self.BODY) is True

        mock_s3.put_object.assert_called_once()
        kwargs = mock_s3.put_object.call_args.kwargs
        assert kwargs["Bucket"] == "bucket"
        assert kwargs["Key"] == "accounts.yaml"
        assert kwargs["Body"] == self.BODY.encode("utf-8")
        assert kwargs["ContentType"] == "application/x-yaml"
        assert (
            kwargs["Metadata"]["content-sha256"]
            == hashlib.sha256(self.BODY.encode("utf-8")).hexdigest()
        )
        assert kwargs["Metadata"]["generated-at"]

    @patch("handler.s3_client")
    def test_store_inventory_first_write(self, mock_s3):
        mock_s3.head_object.side_effect = _client_error("404")

        assert handler.store_inventory("bucket", "accounts.yaml", self.BODY) is True
        mock_s3.put_object.assert_called_once()

    @patch("handler.s3_client")
    def test_store_inventory_head_error_raises(self, mock_s3):
        """Errors other than not-found (e.g. access denied) are not treated as a first write."""
        mock_s3.head_object.side_effect = _client_error("403")

        with pytest.raises(ClientError):
            handler.store_inventory("bucket", "accounts.yaml", self.BODY)
        mock_s3.put_object.assert_not_called()


# ============================================================================
# Tests for bump_conformance_pack function
# ============================================================================


class TestBumpConformancePack:
    """Tests for bump_conformance_pack function."""

    @patch("handler.config_client")
    def test_bump_pack_skips_when_current(self, mock_config):
        mock_config.describe_organization_conformance_packs.return_value = {
            "OrganizationConformancePacks": [
                {
                    "OrganizationConformancePackName": "tagging-compliance",
                    "ConformancePackInputParameters": [
                        {"ParameterName": "InventoryVersion", "ParameterValue": "same"},
                    ],
                }
            ]
        }

        assert (
            handler.bump_conformance_pack("tagging-compliance", "same", TEMPLATE_URI)
            is False
        )
        mock_config.put_organization_conformance_pack.assert_not_called()

    @patch("handler.config_client")
    def test_bump_pack_returns_true_when_reput(self, mock_config):
        mock_config.describe_organization_conformance_packs.return_value = {
            "OrganizationConformancePacks": [
                {"OrganizationConformancePackName": "tagging-compliance"}
            ]
        }

        assert (
            handler.bump_conformance_pack("tagging-compliance", "new", TEMPLATE_URI)
            is True
        )

    @patch("handler.config_client")
    def test_bump_pack_preserves_parameters(self, mock_config):
        mock_config.describe_organization_conformance_packs.return_value = {
            "OrganizationConformancePacks": [
                {
                    "OrganizationConformancePackName": "tagging-compliance",
                    "DeliveryS3Bucket": "awsconfigconforms-delivery",
                    "DeliveryS3KeyPrefix": "tagging",
                    "ExcludedAccounts": ["111111111111"],
                    "ConformancePackInputParameters": [
                        {"ParameterName": "PolicyVersion", "ParameterValue": "p1"},
                        {"ParameterName": "MappingsVersion", "ParameterValue": "m1"},
                        {"ParameterName": "InventoryVersion", "ParameterValue": "old"},
                    ],
                }
            ]
        }

        handler.bump_conformance_pack("tagging-compliance", "new", TEMPLATE_URI)

        mock_config.describe_organization_conformance_packs.assert_called_once_with(
            OrganizationConformancePackNames=["tagging-compliance"]
        )
        mock_config.put_organization_conformance_pack.assert_called_once()
        kwargs = mock_config.put_organization_conformance_pack.call_args.kwargs
        assert kwargs["OrganizationConformancePackName"] == "tagging-compliance"
        assert kwargs["TemplateS3Uri"] == TEMPLATE_URI
        assert kwargs["DeliveryS3Bucket"] == "awsconfigconforms-delivery"
        assert kwargs["DeliveryS3KeyPrefix"] == "tagging"
        assert kwargs["ExcludedAccounts"] == ["111111111111"]
        params = {
            p["ParameterName"]: p["ParameterValue"]
            for p in kwargs["ConformancePackInputParameters"]
        }
        assert params == {
            "PolicyVersion": "p1",
            "MappingsVersion": "m1",
            "InventoryVersion": "new",
        }

    @patch("handler.config_client")
    def test_bump_pack_adds_missing_inventory_version(self, mock_config):
        mock_config.describe_organization_conformance_packs.return_value = {
            "OrganizationConformancePacks": [
                {
                    "OrganizationConformancePackName": "tagging-compliance",
                    "ConformancePackInputParameters": [
                        {"ParameterName": "PolicyVersion", "ParameterValue": "p1"},
                    ],
                }
            ]
        }

        handler.bump_conformance_pack("tagging-compliance", "new", TEMPLATE_URI)

        kwargs = mock_config.put_organization_conformance_pack.call_args.kwargs
        assert "DeliveryS3Bucket" not in kwargs
        assert "DeliveryS3KeyPrefix" not in kwargs
        assert kwargs["ExcludedAccounts"] == []
        assert {
            p["ParameterName"]: p["ParameterValue"]
            for p in kwargs["ConformancePackInputParameters"]
        } == {"PolicyVersion": "p1", "InventoryVersion": "new"}

    @patch("handler.config_client")
    def test_bump_pack_missing_pack_warns(self, mock_config):
        mock_config.describe_organization_conformance_packs.side_effect = _client_error(
            "NoSuchOrganizationConformancePackException",
            "DescribeOrganizationConformancePacks",
        )

        handler.bump_conformance_pack("tagging-compliance", "new", TEMPLATE_URI)

        mock_config.put_organization_conformance_pack.assert_not_called()

    @patch("handler.config_client")
    def test_bump_pack_other_errors_raise(self, mock_config):
        mock_config.describe_organization_conformance_packs.side_effect = _client_error(
            "OrganizationAccessDeniedException",
            "DescribeOrganizationConformancePacks",
        )

        with pytest.raises(ClientError):
            handler.bump_conformance_pack("tagging-compliance", "new", TEMPLATE_URI)


# ============================================================================
# Tests for lambda_handler
# ============================================================================


ENV = {
    "BUCKET_NAME": "tagging-compliance",
    "ACCOUNTS_KEY": "accounts.yaml",
}
PACK_ENV = dict(
    ENV,
    CONFORMANCE_PACK_NAME="tagging-compliance",
    CONFORMANCE_PACK_TEMPLATE_URI=TEMPLATE_URI,
)


def _pack_with_inventory_version(version):
    """A describe_organization_conformance_packs response with the given InventoryVersion."""
    return {
        "OrganizationConformancePacks": [
            {
                "OrganizationConformancePackName": "tagging-compliance",
                "ConformancePackInputParameters": [
                    {"ParameterName": "PolicyVersion", "ParameterValue": "p1"},
                    {"ParameterName": "InventoryVersion", "ParameterValue": version},
                ],
            }
        ]
    }


class TestLambdaHandler:
    """Tests for the main lambda_handler function."""

    @patch.dict(os.environ, PACK_ENV, clear=True)
    @patch("handler.config_client")
    @patch("handler.store_inventory", return_value=True)
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map", return_value={})
    def test_handler_changed_content_writes_and_reputs(
        self, _ou, mock_list, mock_store, mock_config, mock_context, fixture_accounts
    ):
        mock_list.return_value = fixture_accounts
        mock_config.describe_organization_conformance_packs.return_value = (
            _pack_with_inventory_version("old")
        )

        result = handler.lambda_handler({}, mock_context)

        body = handler.render_inventory(fixture_accounts)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        assert result == {"status": "ok", "account_count": 2, "changed": True}
        mock_store.assert_called_once_with("tagging-compliance", "accounts.yaml", body)
        kwargs = mock_config.put_organization_conformance_pack.call_args.kwargs
        assert kwargs["TemplateS3Uri"] == TEMPLATE_URI
        assert {
            "ParameterName": "InventoryVersion",
            "ParameterValue": digest,
        } in kwargs["ConformancePackInputParameters"]

    @patch.dict(os.environ, PACK_ENV, clear=True)
    @patch("handler.config_client")
    @patch("handler.store_inventory", return_value=False)
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map", return_value={})
    def test_handler_unchanged_content_stale_pack_reputs(
        self, _ou, mock_list, _store, mock_config, mock_context, fixture_accounts
    ):
        """A previous run wrote S3 but failed to re-put the pack: reconcile now."""
        mock_list.return_value = fixture_accounts
        mock_config.describe_organization_conformance_packs.return_value = (
            _pack_with_inventory_version("stale")
        )

        result = handler.lambda_handler({}, mock_context)

        digest = hashlib.sha256(
            handler.render_inventory(fixture_accounts).encode("utf-8")
        ).hexdigest()
        assert result["changed"] is False
        mock_config.put_organization_conformance_pack.assert_called_once()
        kwargs = mock_config.put_organization_conformance_pack.call_args.kwargs
        assert {
            "ParameterName": "InventoryVersion",
            "ParameterValue": digest,
        } in kwargs["ConformancePackInputParameters"]

    @patch.dict(os.environ, PACK_ENV, clear=True)
    @patch("handler.config_client")
    @patch("handler.store_inventory", return_value=False)
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map", return_value={})
    def test_handler_unchanged_content_current_pack_no_reput(
        self, _ou, mock_list, _store, mock_config, mock_context, fixture_accounts
    ):
        mock_list.return_value = fixture_accounts
        digest = hashlib.sha256(
            handler.render_inventory(fixture_accounts).encode("utf-8")
        ).hexdigest()
        mock_config.describe_organization_conformance_packs.return_value = (
            _pack_with_inventory_version(digest)
        )

        result = handler.lambda_handler({}, mock_context)

        assert result["changed"] is False
        mock_config.describe_organization_conformance_packs.assert_called_once()
        mock_config.put_organization_conformance_pack.assert_not_called()

    @patch.dict(os.environ, ENV, clear=True)
    @patch("handler.bump_conformance_pack")
    @patch("handler.store_inventory", return_value=True)
    @patch("handler.list_accounts_with_details", return_value=[])
    @patch("handler.build_ou_map", return_value={})
    def test_handler_no_bump_without_pack_name(
        self, _ou, _list, _store, mock_bump, mock_context
    ):
        result = handler.lambda_handler({}, mock_context)

        assert result["changed"] is True
        mock_bump.assert_not_called()

    @patch.dict(
        os.environ, dict(ENV, CONFORMANCE_PACK_NAME="tagging-compliance"), clear=True
    )
    @patch("handler.bump_conformance_pack")
    @patch("handler.store_inventory", return_value=True)
    @patch("handler.list_accounts_with_details", return_value=[])
    @patch("handler.build_ou_map", return_value={})
    def test_handler_no_bump_without_template_uri(
        self, _ou, _list, _store, mock_bump, mock_context
    ):
        result = handler.lambda_handler({}, mock_context)

        assert result["changed"] is True
        mock_bump.assert_not_called()

    @patch.dict(os.environ, {"ACCOUNTS_KEY": "accounts.yaml"}, clear=True)
    def test_handler_missing_bucket_raises(self, mock_context):
        with pytest.raises(ValueError, match="BUCKET_NAME"):
            handler.lambda_handler({}, mock_context)

    @patch.dict(os.environ, ENV, clear=True)
    @patch("handler.store_inventory")
    @patch("handler.build_ou_map", side_effect=Exception("Organizations API Error"))
    def test_handler_build_ou_map_error_raises(self, _ou, mock_store, mock_context):
        with pytest.raises(Exception, match="Organizations API Error"):
            handler.lambda_handler({}, mock_context)
        mock_store.assert_not_called()
