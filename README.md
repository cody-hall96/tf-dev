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

Your workflow currently authenticates to Azure using these repository secrets:

- `AZURE_SENTINEL_CLIENTID_c9fc70795d1640c9b68797dccd01f1ee`
- `AZURE_SENTINEL_TENANTID_c9fc70795d1640c9b68797dccd01f1ee`
- `AZURE_SENTINEL_SUBSCRIPTIONID_c9fc70795d1640c9b68797dccd01f1ee`

These are used by `azure/login@v2` and set the deployment context subscription.

### Where environment secrets are stored and how to work with them

Environment secrets are stored in **GitHub repository settings**, under a specific Environment.

- Path in UI:
  - `Repo -> Settings -> Environments -> <environment-name> -> Environment secrets`
- They are encrypted by GitHub at rest.
- You can list secret names, create new secrets, update, or delete them.
- **You cannot read back an existing secret value** after saving it (GitHub masks and does not reveal it).

If you need to "see" a secret value later, the practical approach is to retrieve it from your source of truth
(password manager, vault, internal runbook) and re-save it in GitHub.

### Exact setup steps (UI)

1. Go to your repository in GitHub.
2. Open **Settings**.
3. Open **Environments**.
4. Create/select an environment (example: `customer-a-prod`).
5. Under **Environment secrets**, add:
   - `AZURE_SENTINEL_CLIENTID`
   - `AZURE_SENTINEL_TENANTID`
   - `AZURE_SENTINEL_SUBSCRIPTIONID`
6. Under **Environment variables**, add:
   - `RESOURCE_GROUP_NAME`
   - `WORKSPACE_NAME`
   - `WORKSPACE_ID`

### CLI management (optional)

Using GitHub CLI (`gh`):

```bash
# List environment secret names
gh secret list --env customer-a-prod

# Set/update an environment secret (value is prompted securely)
gh secret set AZURE_SENTINEL_SUBSCRIPTIONID --env customer-a-prod

# Set/update by piping from stdin
echo "<value>" | gh secret set AZURE_SENTINEL_TENANTID --env customer-a-prod --body -
```

### Recommended per-customer pattern

For each customer/environment (e.g., `customer-a-prod`, `customer-b-prod`):

1. Use one GitHub Environment per customer.
2. Store Azure auth details as **Environment secrets**.
3. Store non-sensitive deployment identifiers as **Environment variables**.
4. Keep workbook content values (`workbookSourceId`) in the matching `*.parameters-<workspaceId>.json` file.

This separates:

- Authentication/subscription context (GitHub secrets), and
- Template content values (parameter files in Git).
