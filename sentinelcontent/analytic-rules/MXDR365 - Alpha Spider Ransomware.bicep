param workspace string

resource workspace_Microsoft_SecurityInsights_19839657_de8a_43e5_aabf_a19044823d79 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/19839657-de8a-43e5-aabf-a19044823d79'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Alpha Spider Ransomware '
    description: 'Detects attempts to create Alternate Data Streams (ADS) in root directories of Windows drives.'
    severity: 'Medium'
    enabled: true
    query: 'DeviceProcessEvents\r\n| where ProcessCommandLine matches regex @"(?i)^[A-Z]:\\\\:.+"'
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
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
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
        ]
      }
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
            columnName: 'FileName'
          }
        ]
      }
      {
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'ProcessId'
            columnName: 'ProcessId'
          }
        ]
      }
      {
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'CommandLine'
            columnName: 'ProcessCommandLine'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
