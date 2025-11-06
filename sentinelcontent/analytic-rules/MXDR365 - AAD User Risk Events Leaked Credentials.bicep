param workspace string

resource workspace_Microsoft_SecurityInsights_804ae68c_7436_456e_8192_196c0e67479d 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/804ae68c-7436-456e-8192-196c0e67479d'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - AAD User Risk Events Leaked Credentials'
    description: 'This query retrieves user risk events related to leaked credentials from Azure Active Directory Identity Protection. It filters the events based on a specified time period and frequency.'
    severity: 'Medium'
    enabled: true
    query: 'let query_frequency = 1d;\nlet query_period = 1d;\nAADUserRiskEvents\n| where TimeGenerated > ago(query_period)\n| where OperationName == "User Risk Detection" and Source == "IdentityProtection" and RiskEventType == "leakedCredentials"\n| summarize minTimeGenerated = min(TimeGenerated), arg_max(TimeGenerated, *) by Id\n| where minTimeGenerated > ago(query_frequency)\n| project\n    TimeGenerated,\n    OperationName,\n    Source,\n    Activity,\n    UserDisplayName,\n    UserPrincipalName,\n    UserId,\n    RiskEventType,\n    RiskState,\n    RiskDetail,\n    RiskLevel,\n    DetectionTimingType'
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 5
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Reconnaissance'
    ]
    techniques: []
    subTechniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    alertDetailsOverride: null
    customDetails: null
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserPrincipalName'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'UserId'
          }
        ]
      }
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'UserId'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
