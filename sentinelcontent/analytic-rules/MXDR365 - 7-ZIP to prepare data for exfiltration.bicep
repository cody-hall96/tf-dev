param workspace string

resource workspace_Microsoft_SecurityInsights_17c102d2_7933_46ea_ab82_4ad6026f7bd7 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/17c102d2-7933-46ea-ab82-4ad6026f7bd7'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - 7-ZIP to prepare data for exfiltration'
    description: 'The following query detects 7-zip activity associated with this threat. 7-ZIP is a legitimate tool used for file archiving; however, unusual 7-ZIP activity combined with other evidence might indicate that an attacker is compressing data for exfiltration.'
    severity: 'Medium'
    enabled: true
    query: 'DeviceProcessEvents | where FileName == "7z.exe" or FileName == "7zFM.exe" | where ProcessCommandLine contains "ProgramData\\\\pst"'
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Exfiltration'
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
