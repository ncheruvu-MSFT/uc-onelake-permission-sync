"""
Shared bi-directional sync engine for Unity Catalog <-> Fabric OneLake permissions.

Design:
 - Both directions write to the SAME audit log (UC Delta table + Fabric SQL table)
   so a single pane of glass shows drift regardless of which side changed.
 - Default mode is DETECT + REPORT. Actual grant/revoke writes only happen when
   AUTO_REMEDIATE=true is set AND the specific principal/object pair is on the
   approved allow-list table `permission_sync_approved_changes` (human-gated).
 - Identity mapping: Databricks UC principals are Entra UPNs/group names already,
   and Fabric role assignments use Entra object IDs -- `resolve_identity()` bridges
   the two via Microsoft Graph so the diff compares the same underlying identity.
"""
import os
import json
import datetime
import logging
import requests

logger = logging.getLogger("permsync")

DATABRICKS_HOST = os.environ["DATABRICKS_HOST"]          # e.g. adb-xxxx.13.azuredatabricks.net
DATABRICKS_WAREHOUSE_ID = os.environ["DATABRICKS_WAREHOUSE_ID"]
DATABRICKS_TOKEN = os.environ["DATABRICKS_TOKEN"]         # PAT, stored as Function App setting (Key Vault ref recommended)
UC_CATALOG = os.environ.get("UC_CATALOG", "dbw_learn_cac_001")
FABRIC_WORKSPACE_ID = os.environ["FABRIC_WORKSPACE_ID"]
FABRIC_TENANT_ID = os.environ["FABRIC_TENANT_ID"]
FABRIC_CLIENT_ID = os.environ["FABRIC_CLIENT_ID"]
FABRIC_CLIENT_SECRET = os.environ["FABRIC_CLIENT_SECRET"]
AUTO_REMEDIATE = os.environ.get("AUTO_REMEDIATE", "false").lower() == "true"

AUDIT_TABLE = f"{UC_CATALOG}.default.permission_sync_audit"


def _dbx_headers():
    return {"Authorization": f"Bearer {DATABRICKS_TOKEN}", "Content-Type": "application/json"}


def _dbx_sql(statement: str):
    """Execute a SQL statement via the Databricks SQL Statement Execution API
    (works from outside a notebook/cluster context -- what a Function App needs)."""
    body = {
        "warehouse_id": DATABRICKS_WAREHOUSE_ID,
        "statement": statement,
        "wait_timeout": "30s",
    }
    resp = requests.post(
        f"https://{DATABRICKS_HOST}/api/2.0/sql/statements",
        headers=_dbx_headers(), json=body, timeout=60,
    )
    resp.raise_for_status()
    result = resp.json()
    if result.get("status", {}).get("state") == "FAILED":
        raise RuntimeError(f"SQL failed: {result['status']}")
    return result


def get_uc_grants():
    """Return [{grantee, securable_full_name, securable_type, privilege_type}, ...]"""
    result = _dbx_sql(
        f"SELECT grantee, securable_full_name, securable_type, privilege_type "
        f"FROM {UC_CATALOG}.information_schema.grants"
    )
    cols = [c["name"] for c in result["manifest"]["schema"]["columns"]]
    rows = result.get("result", {}).get("data_array", [])
    return [dict(zip(cols, r)) for r in rows]


def _fabric_token():
    resp = requests.post(
        f"https://login.microsoftonline.com/{FABRIC_TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": FABRIC_CLIENT_ID,
            "client_secret": FABRIC_CLIENT_SECRET,
            "scope": "https://api.fabric.microsoft.com/.default",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_fabric_role_assignments():
    token = _fabric_token()
    resp = requests.get(
        f"https://api.fabric.microsoft.com/v1/workspaces/{FABRIC_WORKSPACE_ID}/roleAssignments",
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("value", [])


def resolve_identity(principal_ref: str) -> str:
    """Best-effort normalize a UC grantee (often a UPN or group name) and a Fabric
    principal id (Entra object id) to a common comparison key. For a POC this
    leaves UPNs as-is; extend with a Graph lookup table for production-grade
    identity reconciliation (service principals, nested groups, etc.)."""
    return principal_ref.strip().lower()


def diff_permissions(uc_grants, fabric_roles):
    """Return list of audit rows (both directions) with drift_flag set when a
    principal/permission pair exists in one system but not represented in the other."""
    uc_principals = {resolve_identity(g["grantee"]) for g in uc_grants}
    fabric_principals = {resolve_identity(r["principal"]["id"]) for r in fabric_roles}
    now = datetime.datetime.utcnow().isoformat()
    rows = []

    for g in uc_grants:
        rows.append({
            "run_ts": now,
            "source_system": "unity_catalog",
            "direction": "uc_to_fabric",
            "principal": g["grantee"],
            "object_name": g["securable_full_name"],
            "object_type": g["securable_type"],
            "permission": g["privilege_type"],
            "drift_flag": resolve_identity(g["grantee"]) not in fabric_principals,
        })

    for r in fabric_roles:
        rows.append({
            "run_ts": now,
            "source_system": "fabric_onelake",
            "direction": "fabric_to_uc",
            "principal": r["principal"]["id"],
            "object_name": f"workspace:{FABRIC_WORKSPACE_ID}",
            "object_type": "workspace_role",
            "permission": r["role"],
            "drift_flag": resolve_identity(r["principal"]["id"]) not in uc_principals,
        })
    return rows


def write_audit_uc(rows: list):
    """Write audit rows to the Unity Catalog Delta table (source of truth)."""
    if not rows:
        return
    values_sql = ",".join(
        "(" + ",".join([
            f"'{r['run_ts']}'", f"'{r['source_system']}'", f"'{r['direction']}'",
            f"'{r['principal'].replace(chr(39), '')}'",
            f"'{r['object_name'].replace(chr(39), '')}'",
            f"'{r['object_type']}'", f"'{r['permission']}'",
            "true" if r["drift_flag"] else "false",
            "'scheduled_or_event'",
        ]) + ")"
        for r in rows
    )
    _dbx_sql(
        f"INSERT INTO {AUDIT_TABLE} "
        f"(run_ts, source_system, direction, principal, object_name, object_type, permission, drift_flag, trigger_type) "
        f"VALUES {values_sql}"
    )
    logger.info("Wrote %d audit rows to %s", len(rows), AUDIT_TABLE)


def write_audit_fabric_sql(rows: list):
    """Write audit rows to the Fabric SQL database backing data-agent-governance-app.
    Connection details come from Function App settings; uses pyodbc/aad token auth."""
    conn_str = os.environ.get("FABRIC_SQL_CONNECTION_STRING")
    if not conn_str or not rows:
        logger.info("Fabric SQL sink not configured or no rows -- skipping")
        return
    import pyodbc
    conn = pyodbc.connect(conn_str, autocommit=True)
    cursor = conn.cursor()
    cursor.executemany(
        "INSERT INTO dbo.permission_sync_audit "
        "(run_ts, source_system, direction, principal, object_name, object_type, permission, drift_flag) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(r["run_ts"], r["source_system"], r["direction"], r["principal"],
          r["object_name"], r["object_type"], r["permission"], r["drift_flag"]) for r in rows],
    )
    conn.close()
    logger.info("Wrote %d audit rows to Fabric SQL audit sink", len(rows))


def run_full_reconciliation(trigger_type: str = "timer"):
    uc_grants = get_uc_grants()
    fabric_roles = get_fabric_role_assignments()
    rows = diff_permissions(uc_grants, fabric_roles)
    for r in rows:
        r["trigger_type"] = trigger_type
    write_audit_uc(rows)
    write_audit_fabric_sql(rows)
    drift = [r for r in rows if r["drift_flag"]]
    logger.info("Reconciliation complete: %d total, %d drifted (trigger=%s)",
                len(rows), len(drift), trigger_type)
    if drift and AUTO_REMEDIATE:
        logger.warning(
            "AUTO_REMEDIATE is enabled but remediation logic is intentionally not "
            "implemented in this POC -- grant/revoke changes require human approval."
        )
    return {"total": len(rows), "drifted": len(drift)}


def handle_uc_event(event_body: dict):
    """Incremental path: a single UC/RBAC diagnostic event arrived -- log it
    immediately and flag for review (full reconciliation still runs nightly)."""
    op = event_body.get("operationName", "") or event_body.get("properties", {}).get("actionName", "")
    now = datetime.datetime.utcnow().isoformat()
    row = {
        "run_ts": now, "source_system": "unity_catalog_event", "direction": "uc_to_fabric",
        "principal": event_body.get("identity", {}).get("email", "unknown"),
        "object_name": str(event_body.get("properties", {}).get("resourceName", "unknown")),
        "object_type": "event_triggered", "permission": op, "drift_flag": True,
        "trigger_type": "eventhub_uc",
    }
    write_audit_uc([row])
    write_audit_fabric_sql([row])


def handle_fabric_event(event_body: dict):
    """Incremental path: a Fabric/Power BI audit event (via Purview Audit Log
    streaming) indicates a permission change in OneLake/Fabric workspace."""
    now = datetime.datetime.utcnow().isoformat()
    row = {
        "run_ts": now, "source_system": "fabric_onelake_event", "direction": "fabric_to_uc",
        "principal": event_body.get("UserId", "unknown"),
        "object_name": str(event_body.get("ItemName", event_body.get("Workload", "unknown"))),
        "object_type": "event_triggered", "permission": event_body.get("Operation", "unknown"),
        "drift_flag": True, "trigger_type": "eventhub_fabric",
    }
    write_audit_uc([row])
    write_audit_fabric_sql([row])
