@description('Location for all resources')
param location string = resourceGroup().location

@description('Base name used to derive resource names')
param baseName string = 'ucols-permsync'

@description('Databricks workspace hostname, e.g. adb-xxxx.xx.azuredatabricks.net')
param databricksHost string

@description('Databricks SQL Warehouse ID')
param databricksWarehouseId string

@secure()
@description('Databricks personal access token')
param databricksToken string

@description('Unity Catalog catalog name')
param ucCatalog string = 'main'

@description('Target Fabric workspace GUID')
param fabricWorkspaceId string

@description('Entra tenant ID for the Fabric service principal')
param fabricTenantId string

@description('Entra app (client) ID for the Fabric service principal')
param fabricClientId string

@secure()
@description('Entra client secret for the Fabric service principal')
param fabricClientSecret string

@description('Enable gated auto-remediation (default: detect-only)')
param autoRemediate bool = false

var storageAccountName = toLower(replace('st${baseName}', '-', ''))
var ehNamespaceName = '${baseName}-evhns'
var ucEventHubName = 'unity-catalog-permission-events'
var fabricEventHubName = 'fabric-onelake-permission-events'
var functionAppName = 'func-${baseName}'
var appServicePlanName = 'plan-${baseName}'

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: take(storageAccountName, 24)
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource ehNamespace 'Microsoft.EventHub/namespaces@2024-01-01' = {
  name: ehNamespaceName
  location: location
  sku: { name: 'Standard', tier: 'Standard', capacity: 1 }
}

resource ucEventHub 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = {
  parent: ehNamespace
  name: ucEventHubName
  properties: { partitionCount: 4, messageRetentionInDays: 7 }
}

resource fabricEventHub 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = {
  parent: ehNamespace
  name: fabricEventHubName
  properties: { partitionCount: 2, messageRetentionInDays: 7 }
}

resource ucListenRule 'Microsoft.EventHub/namespaces/eventhubs/authorizationRules@2024-01-01' = {
  parent: ucEventHub
  name: 'function-consumer'
  properties: { rights: ['Listen'] }
}

resource fabricListenRule 'Microsoft.EventHub/namespaces/eventhubs/authorizationRules@2024-01-01' = {
  parent: fabricEventHub
  name: 'function-consumer'
  properties: { rights: ['Listen'] }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' }
  properties: {}
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: appServicePlan.id
    reserved: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.11'
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'DATABRICKS_HOST', value: databricksHost }
        { name: 'DATABRICKS_WAREHOUSE_ID', value: databricksWarehouseId }
        { name: 'DATABRICKS_TOKEN', value: databricksToken }
        { name: 'UC_CATALOG', value: ucCatalog }
        { name: 'FABRIC_WORKSPACE_ID', value: fabricWorkspaceId }
        { name: 'FABRIC_TENANT_ID', value: fabricTenantId }
        { name: 'FABRIC_CLIENT_ID', value: fabricClientId }
        { name: 'FABRIC_CLIENT_SECRET', value: fabricClientSecret }
        { name: 'AUTO_REMEDIATE', value: string(autoRemediate) }
        {
          name: 'EVENTHUB_UC_CONNECTION__fullyQualifiedNamespace'
          value: '${ehNamespace.name}.servicebus.windows.net'
        }
        {
          name: 'EVENTHUB_FABRIC_CONNECTION__fullyQualifiedNamespace'
          value: '${ehNamespace.name}.servicebus.windows.net'
        }
      ]
    }
  }
}

// Grant the Function App's managed identity Storage Blob/Queue/Table Data roles
var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var eventHubsDataReceiverRoleId = 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde'

resource storageBlobRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageBlobDataOwnerRoleId)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalType: 'ServicePrincipal'
  }
}

resource storageQueueRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorRoleId)
    principalType: 'ServicePrincipal'
  }
}

resource storageTableRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleId)
    principalType: 'ServicePrincipal'
  }
}

resource ehDataReceiverAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(ehNamespace.id, functionApp.id, eventHubsDataReceiverRoleId)
  scope: ehNamespace
  properties: {
    principalId: functionApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', eventHubsDataReceiverRoleId)
    principalType: 'ServicePrincipal'
  }
}

output functionAppName string = functionApp.name
output storageAccountName string = storage.name
output eventHubNamespace string = ehNamespace.name
