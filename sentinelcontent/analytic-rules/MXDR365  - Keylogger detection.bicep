param workspace string

resource workspace_Microsoft_SecurityInsights_230a4601_04d4_40a4_9475_3ade74be1929 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/230a4601-04d4-40a4-9475-3ade74be1929'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Keylogger detection'
    description: 'This detection rule identifies active keylogging malware by monitoring for direct keylogger indicators within system events across endpoints. The rule performs comprehensive behavioral analysis to detect malicious software that captures keyboard input for credential theft, sensitive data harvesting, and surveillance activities. By searching for explicit keylogger terminology in system telemetry over extended time periods, this detection catches persistent keylogging campaigns that target user authentication data, personal communications, and confidential information for unauthorized access, espionage, or financial fraud operations.'
    severity: 'Medium'
    enabled: true
    query: 'let keystrokeEvents = \n    DeviceEvents\n    | where TimeGenerated > ago(1h)\n    | where AdditionalFields has_any("keylogger", "keystroke", "input capture")\n    | project\n        KeystrokeTime = TimeGenerated,\n        DeviceName,\n        ReportId,\n        InitiatingProcessId,\n        AdditionalFields;\nlet procContext =\n    DeviceProcessEvents\n    | where TimeGenerated > ago(1h)\n    | project\n        Proc_Time = TimeGenerated,\n        DeviceName,\n        Proc_ProcessId = ProcessId,\n        Proc_FileName = FileName,\n        Proc_FolderPath = FolderPath,\n        Proc_InitiatingProcessId = InitiatingProcessId,\n        Proc_InitiatingProcessParentId = InitiatingProcessParentId,\n        Proc_CommandLine = ProcessCommandLine,\n        Proc_AccountName = AccountName;\nkeystrokeEvents\n| join kind=inner (\n    procContext\n    )\n    on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessId == $right.Proc_ProcessId'
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: []
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
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'Proc_AccountName'
          }
        ]
      }
      {
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'CommandLine'
            columnName: 'Proc_CommandLine'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
