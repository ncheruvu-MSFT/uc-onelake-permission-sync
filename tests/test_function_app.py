"""
Tests for function_app.py -- the Azure Functions v2 trigger routing layer.

These tests exercise each trigger's own logic (parsing the event payload,
filtering, calling into permsync_core, error propagation) without needing a
running Azure Functions host. permsync_core's own functions are mocked so
these tests only verify *routing* behavior, not the engine's business logic
(covered separately in test_permsync_core.py).
"""
import json
from unittest.mock import MagicMock, patch

import azure.functions as func
import pytest

import function_app as fa


def _make_eventhub_event(body):
    return func.EventHubEvent(body=json.dumps(body).encode("utf-8"))


# ---------------------------------------------------------------------------
# Timer trigger
# ---------------------------------------------------------------------------

class TestNightlyFullReconciliation:
    @patch("function_app.core.run_full_reconciliation")
    def test_calls_core_with_nightly_trigger_type(self, mock_run):
        mock_run.return_value = {"total": 5, "drifted": 1}
        timer = MagicMock(spec=func.TimerRequest)
        fa.nightly_full_reconciliation(timer)
        mock_run.assert_called_once_with(trigger_type="timer_nightly")

    @patch("function_app.core.run_full_reconciliation", side_effect=RuntimeError("downstream failure"))
    def test_propagates_exceptions_so_the_run_shows_failed(self, mock_run):
        """A failed reconciliation must not be swallowed -- it needs to surface
        as a failed Function execution so alerting/monitoring catches it."""
        timer = MagicMock(spec=func.TimerRequest)
        with pytest.raises(RuntimeError):
            fa.nightly_full_reconciliation(timer)


# ---------------------------------------------------------------------------
# Unity Catalog Event Hub trigger
# ---------------------------------------------------------------------------

class TestUcPermissionEventConsumer:
    @patch("function_app.core.handle_uc_event")
    def test_handles_single_record_dict(self, mock_handle):
        event = _make_eventhub_event({"operationName": "createGrant"})
        fa.uc_permission_event_consumer(event)
        mock_handle.assert_called_once_with({"operationName": "createGrant"})

    @patch("function_app.core.handle_uc_event")
    def test_handles_records_wrapper(self, mock_handle):
        event = _make_eventhub_event({"records": [{"operationName": "deleteGrant"},
                                                    {"operationName": "updatePermissions"}]})
        fa.uc_permission_event_consumer(event)
        assert mock_handle.call_count == 2

    @patch("function_app.core.handle_uc_event")
    def test_handles_bare_list_payload(self, mock_handle):
        event = _make_eventhub_event([{"operationName": "createGrant"}, {"operationName": "changeOwner"}])
        fa.uc_permission_event_consumer(event)
        assert mock_handle.call_count == 2

    @patch("function_app.core.handle_uc_event", side_effect=ValueError("boom"))
    def test_reraises_on_handler_failure(self, mock_handle):
        """Event Hub triggers must re-raise so the platform retries/dead-letters
        instead of silently losing a permission-change event."""
        event = _make_eventhub_event({"operationName": "createGrant"})
        with pytest.raises(ValueError):
            fa.uc_permission_event_consumer(event)

    def test_raises_on_malformed_json(self):
        event = func.EventHubEvent(body=b"not-json")
        with pytest.raises(Exception):
            fa.uc_permission_event_consumer(event)


# ---------------------------------------------------------------------------
# Fabric Event Hub trigger (filters to permission-related operations only)
# ---------------------------------------------------------------------------

class TestFabricPermissionEventConsumer:
    @patch("function_app.core.handle_fabric_event")
    def test_processes_permission_operation(self, mock_handle):
        event = _make_eventhub_event({"Operation": "AddWorkspaceRolePermission", "Workload": "OneLake"})
        fa.fabric_permission_event_consumer(event)
        mock_handle.assert_called_once()

    @patch("function_app.core.handle_fabric_event")
    def test_processes_onelake_workload_even_without_permission_in_name(self, mock_handle):
        event = _make_eventhub_event({"Operation": "ViewItem", "Workload": "OneLake"})
        fa.fabric_permission_event_consumer(event)
        mock_handle.assert_called_once()

    @patch("function_app.core.handle_fabric_event")
    def test_ignores_unrelated_operations(self, mock_handle):
        event = _make_eventhub_event({"Operation": "ViewReport", "Workload": "PowerBI"})
        fa.fabric_permission_event_consumer(event)
        mock_handle.assert_not_called()

    @patch("function_app.core.handle_fabric_event")
    def test_handles_bare_list_payload(self, mock_handle):
        event = _make_eventhub_event([
            {"Operation": "RemovePermission", "Workload": "OneLake"},
            {"Operation": "ViewReport", "Workload": "PowerBI"},  # should be filtered out
        ])
        fa.fabric_permission_event_consumer(event)
        mock_handle.assert_called_once()

    @patch("function_app.core.handle_fabric_event", side_effect=ValueError("boom"))
    def test_reraises_on_handler_failure(self, mock_handle):
        event = _make_eventhub_event({"Operation": "AddPermission", "Workload": "OneLake"})
        with pytest.raises(ValueError):
            fa.fabric_permission_event_consumer(event)


# ---------------------------------------------------------------------------
# HTTP trigger (manual/ops runbook)
# ---------------------------------------------------------------------------

class TestManualSyncTrigger:
    @patch("function_app.core.run_full_reconciliation")
    def test_returns_200_with_json_result_on_success(self, mock_run):
        mock_run.return_value = {"total": 10, "drifted": 2}
        req = func.HttpRequest(method="POST", url="/api/sync/run", body=b"", headers={})
        resp = fa.manual_sync_trigger(req)
        assert resp.status_code == 200
        assert json.loads(resp.get_body()) == {"total": 10, "drifted": 2}
        mock_run.assert_called_once_with(trigger_type="manual_http")

    @patch("function_app.core.run_full_reconciliation", side_effect=RuntimeError("Fabric API unreachable"))
    def test_returns_500_with_error_message_on_failure(self, mock_run):
        """HTTP trigger must not crash the host -- it should report failure as
        a 500 response so callers (and alerting) can react."""
        req = func.HttpRequest(method="POST", url="/api/sync/run", body=b"", headers={})
        resp = fa.manual_sync_trigger(req)
        assert resp.status_code == 500
        assert "Fabric API unreachable" in json.loads(resp.get_body())["error"]
