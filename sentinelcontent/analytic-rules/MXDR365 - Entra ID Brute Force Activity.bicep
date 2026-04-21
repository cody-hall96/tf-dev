param workspace string

resource workspace_Microsoft_SecurityInsights_8e36be8a_2ef2_4ab5_98f1_3e5eaf0a35a3 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/8e36be8a-2ef2-4ab5-98f1-3e5eaf0a35a3'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Entra ID Brute Force Activity'
    description: 'Detects potential Entra ID brute-force behavior by identifying repeated failed sign-in attempts from a single IP address targeting the same user within one hour.'
    severity: 'High'
    enabled: true
    query: '''
let timeframe = 1h;
let failureThreshold = 10;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType != 0 and ResultType != "0"
| where isnotempty(UserPrincipalName) and isnotempty(IPAddress)
| summarize FailedAttempts=count(), Applications=make_set(AppDisplayName, 5), ResultTypes=make_set(ResultType, 5), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by UserPrincipalName, IPAddress
| where FailedAttempts >= failureThreshold
| project TimeGenerated=EndTime, UserPrincipalName, IPAddress, FailedAttempts, StartTime, EndTime, Applications, ResultTypes
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'CredentialAccess'
      'InitialAccess'
    ]
    techniques: [
      'T1110'
    ]
    subTechniques: [
      'T1110.001'
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
          'IP'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: null
    customDetails: {
      FailedAttempts: 'FailedAttempts'
      StartTime: 'StartTime'
      EndTime: 'EndTime'
    }
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
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
