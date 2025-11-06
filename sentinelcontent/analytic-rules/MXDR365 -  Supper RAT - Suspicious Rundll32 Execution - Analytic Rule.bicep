param workspace string

resource workspace_Microsoft_SecurityInsights_7b678821_6506_4b60_a295_142fa310a80b 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/7b678821-6506-4b60-a295-142fa310a80b'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Supper RAT - Suspicious Rundll32 Execution - Analytic Rule'
    description: 'This detection rule identifies suspicious rundll32.exe execution patterns characteristic of Supper RAT malware deployment. The rule monitors for rundll32.exe processes executing DLL files from temporary directories with specific command-line parameters commonly used by this Remote Access Trojan. By analyzing process execution events and filtering for known Supper RAT indicators, this detection catches malware deployment attempts that leverage legitimate Windows utilities for malicious code execution. The rule focuses on rundll32.exe processes launched from non-standard parent processes to reduce false positives while maintaining effective threat detection.'
    severity: 'Medium'
    enabled: true
    query: 'DeviceProcessEvents\r\n| where TimeGenerated > ago(1h)\r\n| where tolower(FileName) == "rundll32.exe"\r\n| where tolower(ProcessCommandLine) has "\\\\appdata\\\\local\\\\temp\\\\"\r\n| where tolower(ProcessCommandLine) has ".dll"\r\n| where tolower(ProcessCommandLine) has_any (",run",",start")\r\n| where tolower(InitiatingProcessParentFileName) !in ("explorer.exe", "services.exe")\r\n| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFileName'
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Execution'
      'DefenseEvasion'
      'Persistence'
      'CredentialAccess'
      'Discovery'
    ]
    techniques: [
      'T1218'
      'T1027'
      'T1547'
      'T1555'
      'T1082'
      'T1083'
    ]
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
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'InitiatingProcessAccountName'
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
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'InitiatingProcessParentFileName'
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
