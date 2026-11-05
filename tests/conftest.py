"""
Shared pytest fixtures for the permission-sync test suite.

permsync_core.py reads several required environment variables at import time
(DATABRICKS_HOST, FABRIC_WORKSPACE_ID, etc.). We set safe dummy values here,
before the module is first imported by any test, so imports never fail and
no test depends on real credentials or network access.
"""
import os
import sys
import pytest

os.environ.setdefault("DATABRICKS_HOST", "adb-test-0000000000000000.0.azuredatabricks.net")
os.environ.setdefault("DATABRICKS_WAREHOUSE_ID", "test-warehouse-id")
os.environ.setdefault("DATABRICKS_TOKEN", "dummy-test-token")
os.environ.setdefault("UC_CATALOG", "test_catalog")
os.environ.setdefault("FABRIC_WORKSPACE_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("FABRIC_TENANT_ID", "11111111-1111-1111-1111-111111111111")
os.environ.setdefault("FABRIC_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
os.environ.setdefault("FABRIC_CLIENT_SECRET", "dummy-test-secret")
os.environ.setdefault("AUTO_REMEDIATE", "false")

# Make the repo root importable (function_app.py / permsync_core.py live there)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def sample_uc_grants():
    """Three UC grants: two principals that also exist in Fabric, one that doesn't."""
    return [
        {"grantee": "alice@contoso.com", "securable_full_name": "main.sales.orders",
         "securable_type": "TABLE", "privilege_type": "SELECT"},
        {"grantee": "bob@contoso.com", "securable_full_name": "main.sales",
         "securable_type": "SCHEMA", "privilege_type": "USE_SCHEMA"},
        {"grantee": "orphan-uc-only@contoso.com", "securable_full_name": "main.finance.ledger",
         "securable_type": "TABLE", "privilege_type": "SELECT"},
    ]


@pytest.fixture
def sample_fabric_roles():
    """Two Fabric role assignments: one overlapping with UC (by lowercase match),
    one that only exists in Fabric."""
    return [
        {"principal": {"id": "alice@contoso.com", "type": "User"}, "role": "Member"},
        {"principal": {"id": "orphan-fabric-only@contoso.com", "type": "User"}, "role": "Viewer"},
    ]


@pytest.fixture
def matching_uc_grants():
    """UC grants whose principals all have a corresponding Fabric role (no drift)."""
    return [
        {"grantee": "Alice@Contoso.com", "securable_full_name": "main.sales.orders",
         "securable_type": "TABLE", "privilege_type": "SELECT"},
    ]


@pytest.fixture
def matching_fabric_roles():
    return [
        {"principal": {"id": "alice@CONTOSO.com", "type": "User"}, "role": "Member"},
    ]
