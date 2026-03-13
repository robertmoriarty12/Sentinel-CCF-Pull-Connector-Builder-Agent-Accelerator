# Sentinel CCF Pull Connector Builder – Lab Guide

This repository contains a **mock Network Log API** (Azure Function App) designed as a repeatable lab environment for building and testing [Microsoft Sentinel Codeless Connector Framework (CCF)](https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector) pull connectors.

The goal of this lab is to:
1. Deploy a live API with realistic network log data that a CCF connector can poll
2. Use the API documentation to configure a CCF API Poller connector in Sentinel
3. Validate that your CCF connector ingests data correctly end-to-end

---

## Repository Structure

```
├── AzureFunctionNetworkLogAPI/
│   ├── function_app.py          # Python Azure Function – two HTTP endpoints
│   ├── host.json                # Azure Functions host configuration
│   ├── requirements.txt         # Python dependencies
│   └── NetworkLogAPI.zip        # Pre-built deployment package
├── azuredeploy_NetworkLogAPI.json   # ARM template – deploys the Function App
├── NetworkLogAPI_API_Documentation.md  # Full API reference (use for CCF connector)
└── README.md                    # This file – lab guide
```

---

## Prerequisites

Before starting, ensure you have the following:

| Requirement | Notes |
|---|---|
| Azure subscription | With Contributor access to a resource group |
| Microsoft Sentinel workspace | An existing Log Analytics workspace with Sentinel enabled |
| Azure CLI | [Install guide](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| GitHub CLI (`gh`) | Optional – only needed if re-pushing the zip |
| Git | For cloning this repository |

---

## Step 1 – Clone the Repository

```bash
git clone https://github.com/robertmoriarty12/Sentinel-CCF-Pull-Connector-Builder-Agent-Accelerator.git
cd Sentinel-CCF-Pull-Connector-Builder-Agent-Accelerator
```

---

## Step 2 – Log in to Azure

```bash
az login --tenant <your-tenant-id>
```

If the browser does not open automatically, use the device code flow:

```bash
az login --tenant <your-tenant-id> --use-device-code
```

Set your target subscription:

```bash
az account set --subscription "<your-subscription-name-or-id>"
```

Verify you're on the right subscription:

```bash
az account show --query "{name:name, id:id}" -o table
```

---

## Step 3 – Create a Resource Group

```bash
az group create --name connectorBuilderAgent --location eastus
```

You can use any region. `eastus` is used as the default in this lab.

---

## Step 4 – Deploy the Function App

Deploy the ARM template using the Azure CLI. You will need:

- **`ApiKey`** – A strong secret string (≥ 8 characters). This will be the API key callers must include in the `X-API-Key` header. Save this value — you will need it when configuring the CCF connector.
- **`AppInsightsWorkspaceResourceID`** – The full Resource ID of your Log Analytics workspace.

### Get your workspace Resource ID

```bash
az monitor log-analytics workspace show \
  --name <your-workspace-name> \
  --resource-group <workspace-rg> \
  --query id -o tsv
```

### Run the deployment

```bash
az deployment group create \
  --name "NetworkLogAPI-Deploy" \
  --resource-group connectorBuilderAgent \
  --template-file azuredeploy_NetworkLogAPI.json \
  --parameters \
      ApiKey="<your-api-key>" \
      AppInsightsWorkspaceResourceID="<workspace-resource-id>"
```

> **PowerShell users:**
> ```powershell
> az deployment group create `
>   --name "NetworkLogAPI-Deploy" `
>   --resource-group connectorBuilderAgent `
>   --template-file azuredeploy_NetworkLogAPI.json `
>   --parameters `
>       ApiKey="<your-api-key>" `
>       AppInsightsWorkspaceResourceID="<workspace-resource-id>"
> ```

Deployment takes approximately 2–3 minutes. When complete, the output will show:

| Output | Description |
|---|---|
| `FunctionAppName` | The deployed Function App name (with unique suffix) |
| `FunctionAppUrl` | Base URL of the Function App |
| `GetNetworkLogsEndpoint` | Full URL for the data endpoint |
| `RefreshDataEndpoint` | Full URL for the refresh endpoint |

---

## Step 5 – Verify the API is Working

Test the `GetNetworkLogs` endpoint with your API key:

```bash
# Replace <FunctionAppName> and <your-api-key> with the values from the deployment output
curl -s -H "X-API-Key: <your-api-key>" \
  "https://<FunctionAppName>.azurewebsites.net/api/GetNetworkLogs?page=1&pageSize=5" | \
  python -m json.tool
```

You should receive a JSON response with 5 network log records and pagination metadata.

**Expected response shape:**
```json
{
  "status": "success",
  "metadata": {
    "totalCount": 50,
    "page": 1,
    "pageSize": 5,
    "totalPages": 10,
    "hasNextPage": true,
    "nextLink": "https://<FunctionAppName>.azurewebsites.net/api/GetNetworkLogs?page=2&pageSize=5"
  },
  "data": [ ... ]
}
```

If you receive a `401 Unauthorized`, double-check the `X-API-Key` header value matches what you set for `ApiKey` during deployment.

---

## Step 6 – Review the API Documentation

Open [NetworkLogAPI_API_Documentation.md](./NetworkLogAPI_API_Documentation.md) for the full API reference.

This document is specifically structured for CCF connector development. Key sections:

- **Authentication** – `X-API-Key` header configuration
- **Pagination** – offset/page-based with `nextLink`
- **Incremental Pull** – `since` query parameter for delta ingestion
- **Data Schema** – full field-by-field breakdown with types and enum values
- **CCF API Poller Connector Configuration** – ready-to-use CCF settings and a sample connector JSON snippet

---

## Step 7 – Build Your CCF Connector

Using the API documentation from Step 6, configure a CCF API Poller connector in Microsoft Sentinel.

Key CCF settings at a glance:

| Setting | Value |
|---|---|
| Auth Type | `APIKey` |
| API Key Header | `X-API-Key` |
| Endpoint | `https://<FunctionAppName>.azurewebsites.net/api/GetNetworkLogs` |
| HTTP Method | `GET` |
| Pagination Type | `NextPageToken` |
| Next Page Token Path | `$.metadata.nextLink` |
| Has Next Page Path | `$.metadata.hasNextPage` |
| Events Array Path | `$.data[*]` |
| Timestamp Field | `timestamp` |
| Incremental Param | `since` |

Refer to [NetworkLogAPI_API_Documentation.md – CCF section](./NetworkLogAPI_API_Documentation.md#ccf-api-poller-connector-configuration) for the full configuration with the sample connector JSON.

---

## Step 8 – Refresh Data (Optional)

Call the `RefreshData` endpoint to regenerate all 50 log records with fresh timestamps anchored to the current time:

```bash
curl -s -X POST -H "X-API-Key: <your-api-key>" \
  "https://<FunctionAppName>.azurewebsites.net/api/RefreshData"
```

This is useful when re-running ingestion tests and you want to simulate a fresh batch of recent events.

---

## Updating the Function App Code

If you modify `function_app.py`, you must rebuild the zip and redeploy:

**PowerShell:**
```powershell
Compress-Archive -Path .\AzureFunctionNetworkLogAPI\* -DestinationPath .\AzureFunctionNetworkLogAPI\NetworkLogAPI.zip -Force
git add AzureFunctionNetworkLogAPI/NetworkLogAPI.zip
git commit -m "Update function app package"
git push
```

Then restart the Function App to pick up the new zip from GitHub:

```bash
az webapp restart --name <FunctionAppName> --resource-group connectorBuilderAgent
```

---

## Cleaning Up

To remove all deployed resources when you're done:

```bash
az group delete --name connectorBuilderAgent --yes --no-wait
```

---

## API Key Security Note

The API key you set at deployment time is stored as an encrypted Azure App Setting (`NETWORK_LOG_API_KEY`). It is never logged or returned in any response. Store your key securely and treat it like a password.
