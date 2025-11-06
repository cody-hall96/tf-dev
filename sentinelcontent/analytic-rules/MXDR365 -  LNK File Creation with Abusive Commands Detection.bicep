param workspace string

resource workspace_Microsoft_SecurityInsights_fc431e37_8b1b_4dc5_8f6f_4c06fb23e07b 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/fc431e37-8b1b-4dc5-8f6f-4c06fb23e07b'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - LNK File Creation with Abusive Commands Detection'
    description: 'This detection rule identifies potentially malicious Windows shortcut (LNK) file creation events that contain suspicious command lines targeting system utilities. It performs real-time monitoring of LNK file creation with an emphasis on non-standard display modes and embedded commands that are commonly used in initial access and execution techniques by threat actors.'
    severity: 'Medium'
    enabled: true
    query: 'let MonitoredCommands = dynamic([".trycloudflare.com@SSL\\\\DavWWWRoot","cmd", "powershell", "conhost", "pwsh", "regsvr32", "rundll32", "bitsadmin", "certutil","mshta"]);\nDeviceEvents\n| where Timestamp > ago(1h)\n| where ActionType == "ShellLinkCreateFileEvent"\n| where tostring(AdditionalFields) contains "ShellLink"\n| where parse_json(AdditionalFields)["ShellLinkShowCommand"] != \'SW_SHOWNORMAL\'\n| extend ShellLinkCommandLine = parse_json(AdditionalFields)["ShellLinkCommandLine"]\n| extend ShellLinkIconPath = parse_json(AdditionalFields)["ShellLinkIconPath"]\n| where ShellLinkCommandLine != ""\n| where ShellLinkCommandLine has_any (MonitoredCommands)\n'
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'DefenseEvasion'
      'Execution'
      'Persistence'
    ]
    techniques: [
      'T1027'
      'T1204'
      'T1547'
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
    customDetails: {}
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
            columnName: 'AccountName'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'InitiatingProcessAccountName'
          }
        ]
      }
      {
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'CommandLine'
            columnName: 'InitiatingProcessCommandLine'
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
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'InitiatingProcessFileName'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
