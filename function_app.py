import logging
import json
import azure.functions as func
import permsync_core as core

app = func.FunctionApp()


@app.timer_trigger(schedule="0 0 2 * * *", arg_name="timer",
                    run_on_startup=False, use_monitor=True)
def nightly_full_reconciliation(timer: func.TimerRequest) -> None:
    """Full bi-directional reconciliation, every night at 02:00 (Function App timezone)."""
    logging.info("Starting nightly UC<->OneLake permission reconciliation")
    result = core.run_full_reconciliation(trigger_type="timer_nightly")
    logging.info("Nightly reconciliation result: %s", json.dumps(result))


@app.function_name(name="uc_permission_event_consumer")
@app.event_hub_message_trigger(
    arg_name="event",
    event_hub_name="unity-catalog-permission-events",
    connection="EVENTHUB_UC_CONNECTION",
    consumer_group="$Default",
)
def uc_permission_event_consumer(event: func.EventHubEvent) -> None:
    """Incremental sync trigger: fires on Unity Catalog grant/revoke/RBAC
    diagnostic log events streamed from Databricks via Azure Diagnostic Settings."""
    try:
        body = json.loads(event.get_body().decode("utf-8"))
        records = body if isinstance(body, list) else body.get("records", [body])
        for rec in records:
            core.handle_uc_event(rec)
    except Exception as ex:
        logging.exception("Failed processing UC permission event: %s", ex)
        raise


@app.function_name(name="fabric_permission_event_consumer")
@app.event_hub_message_trigger(
    arg_name="event",
    event_hub_name="fabric-onelake-permission-events",
    connection="EVENTHUB_FABRIC_CONNECTION",
    consumer_group="$Default",
)
def fabric_permission_event_consumer(event: func.EventHubEvent) -> None:
    """Incremental sync trigger: fires on Fabric/OneLake permission-change audit
    events, delivered via Microsoft Purview Audit Log streaming to Event Hub."""
    try:
        body = json.loads(event.get_body().decode("utf-8"))
        records = body if isinstance(body, list) else [body]
        for rec in records:
            if "Permission" in rec.get("Operation", "") or rec.get("Workload") == "OneLake":
                core.handle_fabric_event(rec)
    except Exception as ex:
        logging.exception("Failed processing Fabric permission event: %s", ex)
        raise


@app.route(route="sync/run", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def manual_sync_trigger(req: func.HttpRequest) -> func.HttpResponse:
    """On-demand full reconciliation, for manual testing or an ops runbook."""
    try:
        result = core.run_full_reconciliation(trigger_type="manual_http")
        return func.HttpResponse(json.dumps(result), status_code=200, mimetype="application/json")
    except Exception as ex:
        logging.exception("Manual sync failed: %s", ex)
        return func.HttpResponse(json.dumps({"error": str(ex)}), status_code=500, mimetype="application/json")
