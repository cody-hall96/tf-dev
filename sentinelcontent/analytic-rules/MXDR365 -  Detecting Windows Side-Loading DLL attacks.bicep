param workspace string

resource workspace_Microsoft_SecurityInsights_c1bf8497_8846_4e24_ac92_b7a2dca54990 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/c1bf8497-8846-4e24-ac92-b7a2dca54990'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Detecting Windows Side-Loading DLL attacks'
    description: 'Windows command line tool licensingdiag.exe poses a potential security risk. This tool, categorized as a â€œliving off the landâ€ utility, can be exploited for side-loading DLL attacks'
    severity: 'Medium'
    enabled: true
    query: 'let DLLLoaded =\r\nDeviceEvents\r\n| where Timestamp > ago(1h)\r\n| where ActionType == @"DriverLoad"\r\n| where FileName endswith ".dll"\r\n| distinct FileName;\r\nDeviceRegistryEvents\r\n| where ActionType == @"RegistryKeyCreated" or ActionType == @"RegistryValueSet"\r\n| where RegistryKey has_any(DLLLoaded)'
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'PrivilegeEscalation'
      'Persistence'
      'DefenseEvasion'
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
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'DeviceName'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'InitiatingProcessFileName'
          }
        ]
      }
      {
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'CommandLine'
            columnName: 'ActionType'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
