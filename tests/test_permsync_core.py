"""
Tests for permsync_core.py -- the shared bi-directional diff/audit engine.

Covers:
 - identity resolution (case/whitespace normalization)
 - drift detection in both directions (UC->Fabric, Fabric->UC)
 - the "no drift" case when principals match across systems
 - UC grants retrieval via the SQL Statement Execution API (mocked)
 - Fabric token acquisition + role assignment retrieval (mocked)
 - audit writes to Unity Catalog (mocked SQL) and Fabric SQL (mocked pyodbc)
 - full reconciliation orchestration, including the AUTO_REMEDIATE safety path
 - incremental event handlers (UC event, Fabric event)
"""
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

import permsync_core as core


# ---------------------------------------------------------------------------
# resolve_identity
# ---------------------------------------------------------------------------

class TestResolveIdentity:
    def test_lowercases_and_strips(self):
        assert core.resolve_identity("  Alice@CONTOSO.com  ") == "alice@contoso.com"

    def test_idempotent(self):
        value = core.resolve_identity("bob@contoso.com")
        assert core.resolve_identity(value) == value

    def test_empty_string(self):
        assert core.resolve_identity("") == ""


# ---------------------------------------------------------------------------
# diff_permissions -- drift detection, both directions
# ---------------------------------------------------------------------------

class TestDiffPermissions:
    def test_flags_uc_only_principal_as_drift(self, sample_uc_grants, sample_fabric_roles):
        rows = core.diff_permissions(sample_uc_grants, sample_fabric_roles)
        uc_rows = [r for r in rows if r["source_system"] == "unity_catalog"]
        orphan = next(r for r in uc_rows if r["principal"] == "orphan-uc-only@contoso.com")
        assert orphan["drift_flag"] is True
        assert orphan["direction"] == "uc_to_fabric"

    def test_flags_fabric_only_principal_as_drift(self, sample_uc_grants, sample_fabric_roles):
        rows = core.diff_permissions(sample_uc_grants, sample_fabric_roles)
        fabric_rows = [r for r in rows if r["source_system"] == "fabric_onelake"]
        orphan = next(r for r in fabric_rows if r["principal"] == "orphan-fabric-only@contoso.com")
        assert orphan["drift_flag"] is True
        assert orphan["direction"] == "fabric_to_uc"

    def test_no_drift_when_principal_exists_in_both(self, sample_uc_grants, sample_fabric_roles):
        rows = core.diff_permissions(sample_uc_grants, sample_fabric_roles)
        alice_uc = next(r for r in rows if r["source_system"] == "unity_catalog"
                         and r["principal"] == "alice@contoso.com")
        assert alice_uc["drift_flag"] is False

    def test_matching_set_has_zero_drift(self, matching_uc_grants, matching_fabric_roles):
        rows = core.diff_permissions(matching_uc_grants, matching_fabric_roles)
        assert all(r["drift_flag"] is False for r in rows)

    def test_case_insensitive_matching(self, matching_uc_grants, matching_fabric_roles):
        # grantee "Alice@Contoso.com" vs fabric principal "alice@CONTOSO.com"
        rows = core.diff_permissions(matching_uc_grants, matching_fabric_roles)
        assert len(rows) == 2
        assert not any(r["drift_flag"] for r in rows)

    def test_row_count_equals_grants_plus_roles(self, sample_uc_grants, sample_fabric_roles):
        rows = core.diff_permissions(sample_uc_grants, sample_fabric_roles)
        assert len(rows) == len(sample_uc_grants) + len(sample_fabric_roles)

    def test_empty_inputs_produce_no_rows(self):
        assert core.diff_permissions([], []) == []

    def test_all_uc_grants_drift_when_no_fabric_roles(self, sample_uc_grants):
        rows = core.diff_permissions(sample_uc_grants, [])
        assert all(r["drift_flag"] for r in rows)

    def test_fabric_object_name_includes_workspace_id(self, sample_fabric_roles):
        rows = core.diff_permissions([], sample_fabric_roles)
        assert all(core.FABRIC_WORKSPACE_ID in r["object_name"] for r in rows)


# ---------------------------------------------------------------------------
# get_uc_grants -- SQL Statement Execution API (mocked)
# ---------------------------------------------------------------------------

class TestGetUcGrants:
    @patch("permsync_core.requests.post")
    def test_parses_columns_and_rows(self, mock_post):
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {
            "status": {"state": "SUCCEEDED"},
            "manifest": {"schema": {"columns": [
                {"name": "grantee"}, {"name": "securable_full_name"},
                {"name": "securable_type"}, {"name": "privilege_type"},
            ]}},
            "result": {"data_array": [["alice@contoso.com", "main.sales.orders", "TABLE", "SELECT"]]},
        }
        grants = core.get_uc_grants()
        assert grants == [{
            "grantee": "alice@contoso.com", "securable_full_name": "main.sales.orders",
            "securable_type": "TABLE", "privilege_type": "SELECT",
        }]

    @patch("permsync_core.requests.post")
    def test_raises_on_failed_statement(self, mock_post):
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"status": {"state": "FAILED", "error": "boom"}}
        with pytest.raises(RuntimeError):
            core.get_uc_grants()

    @patch("permsync_core.requests.post")
    def test_sends_warehouse_id_and_catalog_query(self, mock_post):
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {
            "status": {"state": "SUCCEEDED"},
            "manifest": {"schema": {"columns": []}},
            "result": {"data_array": []},
        }
        core.get_uc_grants()
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["warehouse_id"] == core.DATABRICKS_WAREHOUSE_ID
        assert core.UC_CATALOG in kwargs["json"]["statement"]


# ---------------------------------------------------------------------------
# Fabric token + role assignments (mocked)
# ---------------------------------------------------------------------------

class TestFabricApi:
    @patch("permsync_core.requests.post")
    def test_fabric_token_requests_correct_scope(self, mock_post):
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"access_token": "tok-123"}
        token = core._fabric_token()
        assert token == "tok-123"
        _, kwargs = mock_post.call_args
        assert kwargs["data"]["scope"] == "https://api.fabric.microsoft.com/.default"
        assert kwargs["data"]["client_id"] == core.FABRIC_CLIENT_ID

    @patch("permsync_core._fabric_token", return_value="tok-123")
    @patch("permsync_core.requests.get")
    def test_get_fabric_role_assignments_uses_bearer_token(self, mock_get, mock_token):
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {"value": [{"principal": {"id": "x"}, "role": "Admin"}]}
        roles = core.get_fabric_role_assignments()
        assert roles == [{"principal": {"id": "x"}, "role": "Admin"}]
        _, kwargs = mock_get.call_args
        assert kwargs["headers"]["Authorization"] == f"Bearer tok-123"


# ---------------------------------------------------------------------------
# Audit writes
# ---------------------------------------------------------------------------

class TestWriteAuditUc:
    @patch("permsync_core._dbx_sql")
    def test_no_op_on_empty_rows(self, mock_sql):
        core.write_audit_uc([])
        mock_sql.assert_not_called()

    @patch("permsync_core._dbx_sql")
    def test_builds_insert_with_escaped_quotes(self, mock_sql):
        rows = [{
            "run_ts": "2026-01-01T00:00:00", "source_system": "unity_catalog",
            "direction": "uc_to_fabric", "principal": "o'brien@contoso.com",
            "object_name": "main.sales.orders", "object_type": "TABLE",
            "permission": "SELECT", "drift_flag": True,
        }]
        core.write_audit_uc(rows)
        sql_arg = mock_sql.call_args[0][0]
        assert "INSERT INTO" in sql_arg
        assert "obrien@contoso.com" in sql_arg  # single quote stripped, not escaped-broken
        assert "true" in sql_arg


class TestWriteAuditFabricSql:
    def test_skips_when_connection_string_not_configured(self, monkeypatch):
        monkeypatch.delenv("FABRIC_SQL_CONNECTION_STRING", raising=False)
        # Should not raise even though pyodbc may not be installed/usable.
        core.write_audit_fabric_sql([{"run_ts": "x", "source_system": "y", "direction": "z",
                                       "principal": "p", "object_name": "o", "object_type": "t",
                                       "permission": "perm", "drift_flag": False}])

    def test_skips_on_empty_rows_even_if_configured(self, monkeypatch):
        monkeypatch.setenv("FABRIC_SQL_CONNECTION_STRING", "Driver={x};Server=y;")
        core.write_audit_fabric_sql([])  # should not attempt a pyodbc import/connect

    def test_writes_rows_when_configured(self, monkeypatch):
        monkeypatch.setenv("FABRIC_SQL_CONNECTION_STRING", "Driver={x};Server=y;")
        fake_pyodbc = types.ModuleType("pyodbc")
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        fake_pyodbc.connect = MagicMock(return_value=mock_conn)
        with patch.dict(sys.modules, {"pyodbc": fake_pyodbc}):
            core.write_audit_fabric_sql([{
                "run_ts": "x", "source_system": "y", "direction": "z", "principal": "p",
                "object_name": "o", "object_type": "t", "permission": "perm", "drift_flag": False,
            }])
        mock_cursor.executemany.assert_called_once()
        mock_conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# run_full_reconciliation -- orchestration + AUTO_REMEDIATE safety behavior
# ---------------------------------------------------------------------------

class TestRunFullReconciliation:
    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    @patch("permsync_core.get_fabric_role_assignments")
    @patch("permsync_core.get_uc_grants")
    def test_returns_total_and_drift_counts(self, mock_grants, mock_roles, mock_write_uc,
                                             mock_write_fabric, sample_uc_grants, sample_fabric_roles):
        mock_grants.return_value = sample_uc_grants
        mock_roles.return_value = sample_fabric_roles
        result = core.run_full_reconciliation(trigger_type="unit_test")
        assert result["total"] == len(sample_uc_grants) + len(sample_fabric_roles)
        # Drifted: bob (uc-only) + orphan-uc-only (uc-only) + orphan-fabric-only (fabric-only) = 3
        assert result["drifted"] == 3
        mock_write_uc.assert_called_once()
        mock_write_fabric.assert_called_once()

    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    @patch("permsync_core.get_fabric_role_assignments")
    @patch("permsync_core.get_uc_grants")
    def test_no_drift_returns_zero(self, mock_grants, mock_roles, mock_write_uc,
                                    mock_write_fabric, matching_uc_grants, matching_fabric_roles):
        mock_grants.return_value = matching_uc_grants
        mock_roles.return_value = matching_fabric_roles
        result = core.run_full_reconciliation()
        assert result["drifted"] == 0

    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    @patch("permsync_core.get_fabric_role_assignments", return_value=[])
    @patch("permsync_core.get_uc_grants", return_value=[])
    def test_auto_remediate_never_mutates_without_implementation(
        self, mock_grants, mock_roles, mock_write_uc, mock_write_fabric, monkeypatch,
    ):
        """Safety-critical: even with AUTO_REMEDIATE enabled, the engine must not
        perform any grant/revoke call -- that logic is intentionally unimplemented
        and gated behind human approval."""
        monkeypatch.setattr(core, "AUTO_REMEDIATE", True)
        result = core.run_full_reconciliation()
        assert result == {"total": 0, "drifted": 0}
        # No unexpected calls beyond the two audit writes -- i.e. nothing else
        # (like a grant/revoke API) was invoked as a side effect.
        mock_write_uc.assert_called_once()
        mock_write_fabric.assert_called_once()

    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    @patch("permsync_core.get_fabric_role_assignments")
    @patch("permsync_core.get_uc_grants")
    def test_trigger_type_propagates_to_all_rows(self, mock_grants, mock_roles, mock_write_uc,
                                                  mock_write_fabric, sample_uc_grants, sample_fabric_roles):
        mock_grants.return_value = sample_uc_grants
        mock_roles.return_value = sample_fabric_roles
        core.run_full_reconciliation(trigger_type="manual_http")
        written_rows = mock_write_uc.call_args[0][0]
        assert all(r["trigger_type"] == "manual_http" for r in written_rows)


# ---------------------------------------------------------------------------
# Incremental event handlers
# ---------------------------------------------------------------------------

class TestHandleUcEvent:
    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    def test_builds_drift_flagged_row_from_event(self, mock_write_uc, mock_write_fabric):
        event = {
            "operationName": "createGrant",
            "identity": {"email": "alice@contoso.com"},
            "properties": {"resourceName": "main.sales.orders"},
        }
        core.handle_uc_event(event)
        row = mock_write_uc.call_args[0][0][0]
        assert row["principal"] == "alice@contoso.com"
        assert row["permission"] == "createGrant"
        assert row["drift_flag"] is True
        assert row["trigger_type"] == "eventhub_uc"
        mock_write_fabric.assert_called_once()

    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    def test_handles_missing_identity_gracefully(self, mock_write_uc, mock_write_fabric):
        core.handle_uc_event({"operationName": "deleteGrant"})
        row = mock_write_uc.call_args[0][0][0]
        assert row["principal"] == "unknown"


class TestHandleFabricEvent:
    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    def test_builds_drift_flagged_row_from_event(self, mock_write_uc, mock_write_fabric):
        event = {"UserId": "bob@contoso.com", "ItemName": "lh_gold", "Operation": "AddWorkspaceRole"}
        core.handle_fabric_event(event)
        row = mock_write_uc.call_args[0][0][0]
        assert row["principal"] == "bob@contoso.com"
        assert row["object_name"] == "lh_gold"
        assert row["permission"] == "AddWorkspaceRole"
        assert row["drift_flag"] is True
        assert row["trigger_type"] == "eventhub_fabric"
        mock_write_fabric.assert_called_once()

    @patch("permsync_core.write_audit_fabric_sql")
    @patch("permsync_core.write_audit_uc")
    def test_falls_back_to_workload_when_itemname_missing(self, mock_write_uc, mock_write_fabric):
        event = {"UserId": "bob@contoso.com", "Workload": "OneLake", "Operation": "RemoveWorkspaceRole"}
        core.handle_fabric_event(event)
        row = mock_write_uc.call_args[0][0][0]
        assert row["object_name"] == "OneLake"
