"""
Unit tests for the AWS Organizations account inventory Lambda handler.

Tests cover:
- Organization unit hierarchy building
- Account alias retrieval
- Account details retrieval
- DynamoDB storage operations
- Lambda handler integration
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

import handler

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
def sample_ou_map():
    """A sample organizational unit hierarchy map."""
    return {
        "r-1234": {"name": "root", "parent_id": None},
        "ou-1111": {"name": "engineering", "parent_id": "r-1234"},
        "ou-2222": {"name": "platform", "parent_id": "ou-1111"},
        "ou-3333": {"name": "finance", "parent_id": "r-1234"},
    }


@pytest.fixture
def sample_organizations_response():
    """Sample response from Organizations API for list_accounts."""
    return {
        "Accounts": [
            {
                "Id": "123456789012",
                "Name": "Production Account",
                "Status": "ACTIVE",
            },
            {
                "Id": "210987654321",
                "Name": "Development Account",
                "Status": "ACTIVE",
            },
            {
                "Id": "111222333444",
                "Name": "Suspended Account",
                "Status": "SUSPENDED",
            },
        ]
    }


@pytest.fixture
def mock_context():
    """Mock Lambda context object."""
    context = MagicMock()
    context.aws_request_id = "test-request-id-12345"
    return context


# ============================================================================
# Tests for AccountInfo dataclass
# ============================================================================


class TestAccountInfo:
    """Tests for the AccountInfo dataclass."""

    def test_account_info_creation(self, sample_account_info):
        """Test creating an AccountInfo object."""
        assert sample_account_info.AccountId == "123456789012"
        assert sample_account_info.AccountName == "Production Account"
        assert sample_account_info.OUPath == "root/engineering/platform"
        assert sample_account_info.Status == "ACTIVE"
        assert sample_account_info.LastUpdated is not None

    def test_account_info_default_values(self):
        """Test AccountInfo with default values."""
        account = handler.AccountInfo(
            AccountId="123456789012",
            AccountName="Test Account",
            OUPath="root",
            Status="ACTIVE",
        )
        assert account.LastUpdated is not None


# ============================================================================
# Tests for parse_ou_path function
# ============================================================================


class TestParseOUPath:
    """Tests for parse_ou_path function."""

    def test_parse_ou_path_deep_hierarchy(self, sample_ou_map):
        """Test parsing OU path for deeply nested organizational unit."""
        path = handler.parse_ou_path("ou-2222", sample_ou_map)
        assert path == "root/engineering/platform"

    def test_parse_ou_path_single_level(self, sample_ou_map):
        """Test parsing OU path for single level OU."""
        path = handler.parse_ou_path("ou-1111", sample_ou_map)
        assert path == "root/engineering"

    def test_parse_ou_path_root(self, sample_ou_map):
        """Test parsing OU path for root."""
        path = handler.parse_ou_path("r-1234", sample_ou_map)
        assert path == "root"

    def test_parse_ou_path_nonexistent_ou(self, sample_ou_map):
        """Test parsing OU path for nonexistent OU returns root."""
        path = handler.parse_ou_path("ou-nonexistent", sample_ou_map)
        assert path == "root"

    def test_parse_ou_path_empty_map(self):
        """Test parsing OU path with empty map."""
        path = handler.parse_ou_path("ou-1111", {})
        assert path == "root"


# ============================================================================
# Tests for build_ou_map function
# ============================================================================


class TestBuildOUMap:
    """Tests for build_ou_map function."""

    @patch("handler.organizations_client")
    def test_build_ou_map_success(self, mock_org_client):
        """Test successfully building organizational unit map."""
        # Mock list_roots
        mock_org_client.list_roots.return_value = {
            "Roots": [{"Id": "r-1234", "Name": "root"}]
        }

        # Mock paginator for OUs
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator

        # Mock paginate responses
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
            elif ParentId == "ou-1111":
                return iter(
                    [
                        {
                            "OrganizationalUnits": [
                                {"Id": "ou-2222", "Name": "platform"},
                            ]
                        }
                    ]
                )
            else:
                return iter([{"OrganizationalUnits": []}])

        mock_paginator.paginate.side_effect = paginate_side_effect

        ou_map = handler.build_ou_map()

        assert "r-1234" in ou_map
        assert ou_map["r-1234"]["name"] == "root"
        assert ou_map["r-1234"]["parent_id"] is None
        assert "ou-1111" in ou_map
        assert "ou-3333" in ou_map

    @patch("handler.organizations_client")
    def test_build_ou_map_organizations_error(self, mock_org_client):
        """Test build_ou_map handles Organizations API errors."""
        mock_org_client.list_roots.side_effect = Exception("API Error")

        with pytest.raises(Exception, match="API Error"):
            handler.build_ou_map()


# ============================================================================
# Tests for list_accounts_with_details function
# ============================================================================


class TestListAccountsWithDetails:
    """Tests for list_accounts_with_details function."""

    @patch("handler.organizations_client")
    def test_list_accounts_with_details_success(self, mock_org_client, sample_ou_map):
        """Test successfully listing accounts with details."""
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
            {"Parents": [{"Id": "ou-2222"}]},  # For first account
            {"Parents": [{"Id": "ou-1111"}]},  # For second account
        ]

        accounts = handler.list_accounts_with_details(sample_ou_map)

        assert len(accounts) == 2
        assert accounts[0].AccountId == "123456789012"
        assert accounts[0].AccountName == "Production"
        assert accounts[0].OUPath == "root/engineering/platform"
        assert accounts[1].AccountId == "210987654321"
        assert accounts[1].AccountName == "Development"

    @patch("handler.organizations_client")
    def test_list_accounts_with_details_no_parent(self, mock_org_client, sample_ou_map):
        """Test listing accounts when no parent OU is found."""
        mock_paginator = MagicMock()
        mock_org_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "123456789012", "Name": "Orphan Account", "Status": "ACTIVE"}
                ]
            }
        ]

        mock_org_client.list_parents.return_value = {"Parents": []}

        accounts = handler.list_accounts_with_details(sample_ou_map)

        assert len(accounts) == 1
        assert accounts[0].OUPath == "root"

    @patch("handler.organizations_client")
    def test_list_accounts_with_details_organizations_error(
        self, mock_org_client, sample_ou_map
    ):
        """Test list_accounts_with_details handles Organizations API errors."""
        mock_org_client.get_paginator.side_effect = Exception("API Error")

        with pytest.raises(Exception, match="API Error"):
            handler.list_accounts_with_details(sample_ou_map)


# ============================================================================
# Tests for store_accounts_in_dynamodb function
# ============================================================================


class TestStoreAccountsInDynamoDB:
    """Tests for store_accounts_in_dynamodb function."""

    @patch("handler.dynamodb_client")
    def test_store_accounts_in_dynamodb_success(
        self, mock_dynamodb, sample_account_info
    ):
        """Test successfully storing accounts in DynamoDB."""
        mock_dynamodb.put_item.return_value = {}

        accounts = [sample_account_info]
        stored_count = handler.store_accounts_in_dynamodb(accounts, "test-table")

        assert stored_count == 1
        mock_dynamodb.put_item.assert_called_once()

        # Verify the call arguments
        call_args = mock_dynamodb.put_item.call_args[1]
        assert call_args["TableName"] == "test-table"
        assert call_args["Item"]["AccountId"]["S"] == "123456789012"
        assert call_args["Item"]["AccountName"]["S"] == "Production Account"
        assert call_args["Item"]["OUPath"]["S"] == "root/engineering/platform"
        assert call_args["Item"]["Status"]["S"] == "ACTIVE"

    @patch("handler.dynamodb_client")
    def test_store_accounts_in_dynamodb_multiple(self, mock_dynamodb):
        """Test storing multiple accounts in DynamoDB."""
        mock_dynamodb.put_item.return_value = {}

        accounts = [
            handler.AccountInfo(
                AccountId="123456789012",
                AccountName="Production",
                OUPath="root/prod",
                Status="ACTIVE",
            ),
            handler.AccountInfo(
                AccountId="210987654321",
                AccountName="Development",
                OUPath="root/dev",
                Status="ACTIVE",
            ),
        ]

        stored_count = handler.store_accounts_in_dynamodb(accounts, "test-table")

        assert stored_count == 2
        assert mock_dynamodb.put_item.call_count == 2

    @patch("handler.dynamodb_client")
    def test_store_accounts_in_dynamodb_partial_failure(self, mock_dynamodb):
        """Test partial failure when storing accounts in DynamoDB."""
        # First call succeeds, second fails
        mock_dynamodb.put_item.side_effect = [
            {},  # Success
            Exception("DynamoDB Error"),  # Failure
        ]

        accounts = [
            handler.AccountInfo(
                AccountId="123456789012",
                AccountName="Production",
                OUPath="root/prod",
                Status="ACTIVE",
            ),
            handler.AccountInfo(
                AccountId="210987654321",
                AccountName="Development",
                OUPath="root/dev",
                Status="ACTIVE",
            ),
        ]

        stored_count = handler.store_accounts_in_dynamodb(accounts, "test-table")

        # Should have stored one account before the error
        assert stored_count == 1
        assert mock_dynamodb.put_item.call_count == 2

    @patch("handler.dynamodb_client")
    def test_store_accounts_in_dynamodb_empty_list(self, mock_dynamodb):
        """Test storing empty account list."""
        stored_count = handler.store_accounts_in_dynamodb([], "test-table")

        assert stored_count == 0
        mock_dynamodb.put_item.assert_not_called()


# ============================================================================
# Tests for environment variable validation in lambda_handler
# ============================================================================


class TestEnvironmentValidation:
    """Tests for environment variable validation."""

    @patch.dict(
        os.environ,
        {
            "DYNAMODB_TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
        },
    )
    @patch("handler.store_accounts_in_dynamodb")
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map")
    def test_environment_validation_success(
        self, mock_build_ou_map, mock_list_accounts, mock_store_accounts, mock_context
    ):
        """Test environment validation succeeds with DYNAMODB_TABLE_ARN set."""
        mock_build_ou_map.return_value = {}
        mock_list_accounts.return_value = []
        mock_store_accounts.return_value = 0

        result = handler.lambda_handler({}, mock_context)
        assert result["statusCode"] == 200
        assert (
            result["body"]["message"]
            == "Successfully synced AWS Organizations accounts"
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_environment_validation_missing_table_name(self, mock_context):
        """Test environment validation fails when DYNAMODB_TABLE_ARN is missing."""
        result = handler.lambda_handler({}, mock_context)
        assert result["statusCode"] == 500
        assert "DYNAMODB_TABLE_ARN" in result["body"]["error"]


# ============================================================================
# Tests for lambda_handler integration
# ============================================================================


class TestLambdaHandler:
    """Tests for the main lambda_handler function."""

    @patch.dict(
        os.environ,
        {
            "DYNAMODB_TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
        },
    )
    @patch("handler.store_accounts_in_dynamodb")
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map")
    def test_lambda_handler_success(
        self,
        mock_build_ou_map,
        mock_list_accounts,
        mock_store_accounts,
        mock_context,
    ):
        """Test lambda handler successfully syncs accounts."""
        sample_ou_map = {"r-1234": {"name": "root", "parent_id": None}}
        mock_build_ou_map.return_value = sample_ou_map

        sample_accounts = [
            handler.AccountInfo(
                AccountId="123456789012",
                AccountName="Production",
                OUPath="root",
                Status="ACTIVE",
            ),
        ]
        mock_list_accounts.return_value = sample_accounts
        mock_store_accounts.return_value = 1

        result = handler.lambda_handler({}, mock_context)

        assert result["statusCode"] == 200
        assert result["body"]["stored_count"] == 1
        assert result["body"]["total_count"] == 1
        assert "Successfully synced" in result["body"]["message"]

        mock_build_ou_map.assert_called_once()
        mock_list_accounts.assert_called_once_with(sample_ou_map)
        mock_store_accounts.assert_called_once_with(
            accounts=sample_accounts,
            table_arn="arn:aws:dynamodb:us-east-1:123456789012:table/test-table",
        )

    @patch.dict(
        os.environ,
        {
            "DYNAMODB_TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
        },
    )
    @patch("handler.build_ou_map")
    def test_lambda_handler_missing_environment(self, mock_build_ou_map, mock_context):
        """Test lambda handler with missing environment variable."""
        # This test needs to clear the environment after patching
        with patch.dict(os.environ, {}, clear=True):
            result = handler.lambda_handler({}, mock_context)
            assert result["statusCode"] == 500
            assert "error" in result["body"]

    @patch.dict(os.environ, {"DYNAMODB_TABLE_NAME": "test-table"})
    @patch("handler.build_ou_map")
    def test_lambda_handler_build_ou_map_error(self, mock_build_ou_map, mock_context):
        """Test lambda handler handles build_ou_map errors."""
        mock_build_ou_map.side_effect = Exception("Organizations API Error")

        result = handler.lambda_handler({}, mock_context)

        assert result["statusCode"] == 500
        assert "Failed to sync" in result["body"]["message"]
        assert "error" in result["body"]

    @patch.dict(
        os.environ,
        {
            "DYNAMODB_TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
        },
    )
    @patch("handler.store_accounts_in_dynamodb")
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map")
    def test_lambda_handler_multiple_accounts(
        self,
        mock_build_ou_map,
        mock_list_accounts,
        mock_store_accounts,
        mock_context,
    ):
        """Test lambda handler with multiple accounts."""
        sample_ou_map = {"r-1234": {"name": "root", "parent_id": None}}
        mock_build_ou_map.return_value = sample_ou_map

        sample_accounts = [
            handler.AccountInfo(
                AccountId="123456789012",
                AccountName="Production",
                OUPath="root/prod",
                Status="ACTIVE",
            ),
            handler.AccountInfo(
                AccountId="210987654321",
                AccountName="Development",
                OUPath="root/dev",
                Status="ACTIVE",
            ),
            handler.AccountInfo(
                AccountId="111222333444",
                AccountName="Staging",
                OUPath="root/staging",
                Status="ACTIVE",
            ),
        ]
        mock_list_accounts.return_value = sample_accounts
        mock_store_accounts.return_value = 3

        result = handler.lambda_handler({}, mock_context)

        assert result["statusCode"] == 200
        assert result["body"]["stored_count"] == 3
        assert result["body"]["total_count"] == 3

    @patch.dict(
        os.environ,
        {
            "DYNAMODB_TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
        },
    )
    @patch("handler.store_accounts_in_dynamodb")
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map")
    def test_lambda_handler_no_accounts(
        self,
        mock_build_ou_map,
        mock_list_accounts,
        mock_store_accounts,
        mock_context,
    ):
        """Test lambda handler with no accounts in organization."""
        sample_ou_map = {"r-1234": {"name": "root", "parent_id": None}}
        mock_build_ou_map.return_value = sample_ou_map

        mock_list_accounts.return_value = []
        mock_store_accounts.return_value = 0

        result = handler.lambda_handler({}, mock_context)

        assert result["statusCode"] == 200
        assert result["body"]["stored_count"] == 0
        assert result["body"]["total_count"] == 0

    @patch.dict(
        os.environ,
        {
            "DYNAMODB_TABLE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
        },
    )
    @patch("handler.store_accounts_in_dynamodb")
    @patch("handler.list_accounts_with_details")
    @patch("handler.build_ou_map")
    def test_lambda_handler_partial_store_failure(
        self,
        mock_build_ou_map,
        mock_list_accounts,
        mock_store_accounts,
        mock_context,
    ):
        """Test lambda handler when some accounts fail to store."""
        sample_ou_map = {"r-1234": {"name": "root", "parent_id": None}}
        mock_build_ou_map.return_value = sample_ou_map

        sample_accounts = [
            handler.AccountInfo(
                AccountId="123456789012",
                AccountName="Production",
                OUPath="root",
                Status="ACTIVE",
            ),
            handler.AccountInfo(
                AccountId="210987654321",
                AccountName="Development",
                OUPath="root",
                Status="ACTIVE",
            ),
        ]
        mock_list_accounts.return_value = sample_accounts
        # Only 1 account stored successfully out of 2
        mock_store_accounts.return_value = 1

        result = handler.lambda_handler({}, mock_context)

        assert result["statusCode"] == 200
        assert result["body"]["stored_count"] == 1
        assert result["body"]["total_count"] == 2


# ============================================================================
# Tests for DynamoDB item format
# ============================================================================


class TestDynamoDBItemFormat:
    """Tests for validating DynamoDB item format."""

    @patch("handler.dynamodb_client")
    def test_dynamodb_item_format_correctness(self, mock_dynamodb):
        """Test that account info is stored in correct DynamoDB format."""
        mock_dynamodb.put_item.return_value = {}

        account = handler.AccountInfo(
            AccountId="123456789012",
            AccountName="Test Account",
            OUPath="root/test",
            Status="ACTIVE",
        )

        handler.store_accounts_in_dynamodb([account], "test-table")

        # Verify the item format
        call_args = mock_dynamodb.put_item.call_args[1]
        item = call_args["Item"]

        # All fields should be in DynamoDB format with type descriptors
        assert isinstance(item["AccountId"], dict)
        assert "S" in item["AccountId"]
        assert item["AccountId"]["S"] == "123456789012"

        assert isinstance(item["AccountName"], dict)
        assert "S" in item["AccountName"]

        assert isinstance(item["OUPath"], dict)
        assert "S" in item["OUPath"]

        assert isinstance(item["Status"], dict)
        assert "S" in item["Status"]

        assert isinstance(item["LastUpdated"], dict)
        assert "S" in item["LastUpdated"]
