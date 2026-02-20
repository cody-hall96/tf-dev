# tf-dev

## Tenant-agnostic Sentinel workbook deployment

The workbook template at `sentinelcontent/workbooks/patriot-mxdr-performance.json` is now tenant-agnostic:

- `parameters.workbookSourceId.defaultValue` is a placeholder (not a customer GUID).
- Hardcoded `crossComponentResources` subscription lists in `serializedData` are replaced with `"{Workspace}"`.
- `fallbackResourceIds` is also set to `"{Workspace}"`.

### How to pass customer-specific values

Use ARM parameter files next to the workbook template. The deployment script auto-discovers:

- `*.parameters-<workspaceId>.json` (workspace-specific), then
- `*.parameters.json` (default).

For this workbook, create a file like:

`sentinelcontent/workbooks/patriot-mxdr-performance.parameters-<workspaceId>.json`

Example:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workbookDisplayName": {
      "value": "Patriot MXDR SOC Performance"
    },
    "workbookType": {
      "value": "sentinel"
    },
    "workbookSourceId": {
      "value": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/microsoft.operationalinsights/workspaces/<workspace-name>"
    }
  }
}
```

## GitHub secrets and workflow configuration

Your workflow already authenticates to Azure using three secrets:

- `AZURE_SENTINEL_CLIENTID_c9fc70795d1640c9b68797dccd01f1ee`
- `AZURE_SENTINEL_TENANTID_c9fc70795d1640c9b68797dccd01f1ee`
- `AZURE_SENTINEL_SUBSCRIPTIONID_c9fc70795d1640c9b68797dccd01f1ee`

These are used by `azure/login@v2` and set the deployment context subscription.

### Recommended per-customer pattern

For each customer/environment (e.g., `customer-a-prod`, `customer-b-prod`):

1. Create a GitHub **Environment**.
2. Add environment secrets:
   - `AZURE_SENTINEL_CLIENTID`
   - `AZURE_SENTINEL_TENANTID`
   - `AZURE_SENTINEL_SUBSCRIPTIONID`
3. Add environment variables (or repo variables) for:
   - `RESOURCE_GROUP_NAME`
   - `WORKSPACE_NAME`
   - `WORKSPACE_ID`
4. Point the job to the right environment and use those environment-level values.
5. Keep workbook-specific `workbookSourceId` in the matching `*.parameters-<workspaceId>.json` file.

This separates:

- Authentication/subscription context (GitHub secrets), and
- Template content values (parameter files in Git).
