# uc-onelake-permission-sync

Bi-directional, auditable permission synchronization between **Databricks Unity
Catalog** grants and **Microsoft Fabric OneLake** workspace role assignments —
built as an Azure Function App with both scheduled and event-driven triggers.

> Reference implementation / starting point. Validate against your own
> governance, identity-mapping, and change-management requirements before
> running in production.

## Why

Unity Catalog and Fabric/OneLake are two separate permission systems that
increasingly sit on top of the *same underlying data* (via Lakehouse
Federation / Mirrored Azure Databricks Catalogs, or OneLake shortcuts). Drift
between the two — a principal granted in one system but not represented in
the other — is a real governance risk. This project detects that drift,
audits it from both directions, and (optionally, behind an explicit flag)
supports remediation.

## Architecture

```
 Databricks Unity Catalog                     Microsoft Fabric / OneLake
 ┌─────────────────────┐                     ┌──────────────────────────┐
 │ information_schema   │                     │ Workspace role           │
 │   .grants            │                     │   assignments (Graph)    │
 └──────────┬───────────┘                     └────────────┬─────────────┘
            │ Diagnostic Settings                           │ Purview Audit
            │ (unityCatalog, RBAC logs)                     │ Log streaming
            ▼                                               ▼
   Event Hub: unity-catalog-        Event Hub: fabric-onelake-
   permission-events                permission-events
            │                                               │
            └───────────────────┬───────────────────────────┘
                                 ▼
                    Azure Function App (this repo)
                    ┌───────────────────────────────┐
                    │ • Timer trigger (nightly full  │
                    │   reconciliation, both dirs)   │
                    │ • Event Hub trigger x2         │
                    │   (incremental, near real-time)│
                    │ • HTTP trigger (manual/ops)     │
                    └───────────────┬────────────────┘
                                    ▼
                     Audit sink (dual-write)
              ┌─────────────────────┬─────────────────────┐
              │ UC Delta table       │ Fabric SQL database │
              │ (source of truth)    │ (governance app)    │
              └─────────────────────┴─────────────────────┘
```

**Safety model:** the default mode is **detect + report only**. The engine
never silently grants or revokes permissions. Setting `AUTO_REMEDIATE=true`
enables a path for gated, approved remediation — implement your own
approval-table check before calling any grant/revoke API in production.

## Repo layout

```
function_app.py        # Azure Functions v2 Python entry point (3 triggers)
permsync_core.py        # Shared diff/audit engine used by all triggers
requirements.txt
host.json
infra/
  main.bicep             # Event Hub namespace + 2 hubs, storage, Function App
  main.parameters.json
.github/workflows/
  deploy.yml              # OIDC-based CI/CD to Azure (no stored secrets)
```

## Prerequisites

- An existing **Azure Databricks workspace** with Unity Catalog enabled and a
  SQL Warehouse (serverless recommended) for the [SQL Statement Execution
  API](https://docs.databricks.com/api/workspace/statementexecution).
- An existing **Microsoft Fabric workspace** you want to reconcile against.
- A Microsoft Entra **app registration** (service principal) with Fabric API
  access (tenant setting *"Service principals can call Fabric public APIs"*
  must be enabled), added as at least Contributor on the target Fabric
  workspace.
- A Databricks **personal access token** (or, preferably, OAuth
  machine-to-machine credentials — swap in `permsync_core.py`) with read
  access to `information_schema.grants` on the target catalog.

## Configuration (Function App settings)

| Setting | Description |
|---|---|
| `DATABRICKS_HOST` | Workspace hostname, e.g. `adb-xxxx.xx.azuredatabricks.net` |
| `DATABRICKS_WAREHOUSE_ID` | SQL Warehouse ID used for the Statement Execution API |
| `DATABRICKS_TOKEN` | Databricks PAT (use a Key Vault reference in production) |
| `UC_CATALOG` | Unity Catalog catalog name to reconcile |
| `FABRIC_WORKSPACE_ID` | Target Fabric workspace GUID |
| `FABRIC_TENANT_ID` / `FABRIC_CLIENT_ID` / `FABRIC_CLIENT_SECRET` | Service principal credentials for Fabric API calls |
| `AUTO_REMEDIATE` | `true`/`false` — default `false` (detect-only) |
| `EVENTHUB_UC_CONNECTION` | Listen-only connection string/identity config for the UC events hub |
| `EVENTHUB_FABRIC_CONNECTION` | Listen-only connection string/identity config for the Fabric events hub |
| `FABRIC_SQL_CONNECTION_STRING` | Optional: ODBC connection string for the Fabric SQL audit sink |

## Deploying

### Option A — GitHub Actions (recommended, OIDC, no secrets stored)

See `.github/workflows/deploy.yml`. Configure repository secrets/variables
for `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` (federated
credential, no client secret needed) and push to `main`.

### Option B — Bicep + manual deploy

```bash
az deployment group create -g <your-rg> -f infra/main.bicep -p infra/main.parameters.json
func azure functionapp publish <function-app-name> --python
```

> **Note on storage account policies:** some tenants (e.g. landing-zone /
> security-baseline subscriptions) enforce `allowSharedKeyAccess=false` and
> `publicNetworkAccess=Disabled` on all new storage accounts. Azure
> Functions deployment tooling for Flex/Consumption plans currently expects
> key-based or public blob access for the deployment package upload. If you
> hit `BlobUploadFailedException: Key based authentication is not
> permitted`, either (a) use an Elastic Premium plan with VNet integration
> + Private Endpoint to the storage account, or (b) deploy via this repo's
> GitHub Actions workflow, which in some environments succeeds where local
> CLI deployment does not.

## Event-driven triggers in depth

- **Unity Catalog → Fabric**: Databricks workspace Diagnostic Settings stream
  the `unityCatalog` and `RBAC` log categories to an Event Hub. Any
  grant/revoke/ownership-change event triggers an incremental audit write
  immediately, in addition to the nightly full reconciliation.
- **Fabric → Unity Catalog**: Microsoft Purview **Audit (Premium) log
  streaming** forwards Fabric/OneLake workload audit events to a second
  Event Hub. Permission-related operations trigger the same incremental
  audit path.

## License

MIT — see [LICENSE](LICENSE).
