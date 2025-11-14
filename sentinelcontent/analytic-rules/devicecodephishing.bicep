param workspace string

resource workspace_Microsoft_SecurityInsights_ad2948f0_bd6e_4cde_aec9_2b1bad210ba8 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/ad2948f0-bd6e-4cde-aec9-2b1bad210ba8'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Device Code Phishing '
    description: 'The query is looking for potential device code phishing by finding sign-ins with both error code 50199 (additional approval required) and error code 0 (success).'
    severity: 'Medium'
    enabled: true
    query: '''
let suspiciousids=
SigninLogs
| where TimeGenerated > ago (7d)
| where ResultType in (0,50199)
| summarize Results=make_set(ResultType) by CorrelationId
| where Results has_all (0, 50199)
| distinct CorrelationId;
SigninLogs
| where CorrelationId in (suspiciousids)
| project TimeGenerated, UserPrincipalName, Location, IPAddress, UserAgent, ResultType
'''
    queryFrequency: 'P7D'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 5
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'InitialAccess'
    ]
    techniques: []
    subTechniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
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
            identifier: 'Name'
            columnName: 'UserAgent'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'UserPrincipalName'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
