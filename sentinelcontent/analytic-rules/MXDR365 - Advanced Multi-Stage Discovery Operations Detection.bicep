param workspace string

resource workspace_Microsoft_SecurityInsights_ffd82277_9da7_47fc_b4a2_ed0c5812b100 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/ffd82277-9da7-47fc-b4a2-ed0c5812b100'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Advanced Multi-Stage Discovery Operations Detection'
    description: 'This detection rule identifies sophisticated adversary discovery and reconnaissance activities by analyzing process execution patterns across multiple systems. It employs behavioral pattern matching to detect both rapid multi-category discovery commands and methodical sequential enumeration techniques commonly used during the reconnaissance phase of attacks.'
    severity: 'Medium'
    enabled: false
    query: 'let timeframe = 1h;\nlet historicalWindow = 7d;\n// Whitelisted process names\nlet Whitelisted_FileNames = dynamic([\n    "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe", "brave.exe",\n    "AcroCEF.exe", "Acrobat.exe", "AdobeGCClient.exe",\n    "OUTLOOK.EXE", "EXCEL.EXE", "WINWORD.EXE", "POWERPNT.EXE",\n    "deviceenroller.exe", "svchost.exe", "services.exe",\n    "mdworker", "mdimportworker", "ditto", "Electron"  // reduce false positives\n    ]);\n// Normalization function\nlet normalize = (cmd: string) {\n    let step1 = replace_regex(cmd, @\'\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b\', \'[GUID]\');\n    let step2 = replace_regex(step1, @\'\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b\', \'[IP]\');\n    let step3 = replace_regex(step2, @\'\\b[A-Fa-f0-9]{32,}\\b\', \'[HASH]\');\n    let step4 = replace_regex(step3, @\'\\b\\d{4}-\\d{2}-\\d{2}\\b\', \'[DATE]\');\n    let step5 = replace_regex(step4, @\'\\b\\d{6,}\\b\', \'[ID]\');\n    let step6 = replace_regex(step5, @\'\\\\\\\\[^\\\\]+\\\\[^\\\\]+\', \'[UNC_PATH]\');\n    let step7 = replace_regex(step6, @\'C:\\\\Users\\\\[^\\\\]+\\\\\', \'C:\\\\Users\\\\[USER]\\\\\');\n    tolower(step7)\n};\n// Step 1: Aggregate hourly command counts\nlet historicalHourlyCounts =\n    DeviceProcessEvents\n    | where TimeGenerated between (ago(historicalWindow) .. ago(timeframe))\n    | where ProcessCommandLine matches regex @"(?i)(\\bid\\b|whoami|systeminfo|ifconfig|netstat|\\bps\\b|\\bls\\b|tasklist|\\bnet\\b|\\bwmic\\b|Get-[\\w-]+|hostname|arp|dig|nslookup|\\busers?\\b)"\n    | where not(\n    tolower(ProcessCommandLine) contains "chrome helper" or\n    tolower(ProcessCommandLine) contains "code helper" or\n    tolower(ProcessCommandLine) contains "google chrome.app" or\n    tolower(ProcessCommandLine) contains "visual studio code.app" or\n    tolower(ProcessCommandLine) contains "electron" or\n    tolower(ProcessCommandLine) contains "--type=renderer" or\n    tolower(ProcessCommandLine) contains "--type=utility" or\n    tolower(ProcessCommandLine) contains "--user-data-dir" or\n    tolower(ProcessCommandLine) contains "--sandbox-type=none" or\n    tolower(ProcessCommandLine) contains "jspawnhelper" or\n    tolower(ProcessCommandLine) contains "rubymine.app"\n)\n    | summarize HourlyCount = count() by DeviceId, AccountName, AccountDomain, bin(TimeGenerated, 1h);\n// Step 2: Compute per-entity baseline\nlet statsPerUserDevice =\n    historicalHourlyCounts\n    | summarize\n        HistoricalCount = sum(HourlyCount),\n        AvgCommandsPerHour = avg(HourlyCount),\n        StdDevCommandsPerHour = stdev(HourlyCount)\n        by DeviceId, AccountName, AccountDomain;\n// Step 3: Analyze current activity\nlet currentActivity =\n    DeviceProcessEvents\n    | where TimeGenerated > ago(timeframe)\n    | where ProcessCommandLine matches regex @"(?i)(\\bid\\b|whoami|systeminfo|ifconfig|netstat|\\bps\\b|\\bls\\b|tasklist|\\bnet\\b|\\bwmic\\b|Get-[\\w-]+|hostname|arp|dig|nslookup|\\busers?\\b)"\n    | where not(FileName has_any (Whitelisted_FileNames))\n    | where not(\n    tolower(ProcessCommandLine) contains "chrome helper" or\n    tolower(ProcessCommandLine) contains "code helper" or\n    tolower(ProcessCommandLine) contains "google chrome.app" or\n    tolower(ProcessCommandLine) contains "visual studio code.app" or\n    tolower(ProcessCommandLine) contains "electron" or\n    tolower(ProcessCommandLine) contains "--type=renderer" or\n    tolower(ProcessCommandLine) contains "--type=utility" or\n    tolower(ProcessCommandLine) contains "--user-data-dir" or\n    tolower(ProcessCommandLine) contains "--sandbox-type=none" or\n    tolower(ProcessCommandLine) contains "jspawnhelper" or\n    tolower(ProcessCommandLine) contains "rubymine.app"\n)\n    | extend NormalizedCommand = normalize(ProcessCommandLine)\n    | extend\n        DiscoveryTypes = dynamic([]),\n        MaxDiscoverySeverity = 0\n    // User Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(\\$env:username|whoami|id\\s|users?|passwd|Win32_UserAccount|Get-LocalUser)",\n                             array_concat(DiscoveryTypes, dynamic(["User Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(\\$env:username|whoami|id\\s|users?|passwd|Win32_UserAccount|Get-LocalUser)",\n                           2,\n                           MaxDiscoverySeverity\n                       )\n    // System Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(systeminfo|Get-ComputerInfo|uname -a|hostnamectl|lshw)",\n                             array_concat(DiscoveryTypes, dynamic(["System Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(systeminfo|Get-ComputerInfo|uname -a|hostnamectl|lshw)",\n                           max_of(MaxDiscoverySeverity, 2),\n                           MaxDiscoverySeverity\n                       )\n    // Network Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(ifconfig|ipconfig|route|arp -a|netstat|nslookup|dig|host\\s|broadcast|Get-NetIPAddress)",\n                             array_concat(DiscoveryTypes, dynamic(["Network Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(ifconfig|ipconfig|route|arp -a|netstat|nslookup|dig|host\\s|broadcast|Get-NetIPAddress)",\n                           max_of(MaxDiscoverySeverity, 3),\n                           MaxDiscoverySeverity\n                       )\n    // Process Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(ps(\\s|\\.exe)|tasklist|Get-Process|wmic process)",\n                             array_concat(DiscoveryTypes, dynamic(["Process Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(ps(\\s|\\.exe)|tasklist|Get-Process|wmic process)",\n                           max_of(MaxDiscoverySeverity, 2),\n                           MaxDiscoverySeverity\n                       )\n    // Shares Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(net(\\s+)share|Get-SmbShare|mount|findmnt|showmount)",\n                             array_concat(DiscoveryTypes, dynamic(["Shares Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(net(\\s+)share|Get-SmbShare|mount|findmnt|showmount)",\n                           max_of(MaxDiscoverySeverity, 3),\n                           MaxDiscoverySeverity\n                       )\n    // Domain Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(nltest|dsgetdc|Get-ADDomain|ldapsearch|dig\\s+(\\w+\\.)+\\w+)",\n                             array_concat(DiscoveryTypes, dynamic(["Domain Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(nltest|dsgetdc|Get-ADDomain|ldapsearch|dig\\s+(\\w+\\.)+\\w+)",\n                           max_of(MaxDiscoverySeverity, 4),\n                           MaxDiscoverySeverity\n                       )\n    // File Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(dir\\s|ls\\s|find\\s|grep\\s|type\\s|cat\\s|more\\s|bookmarks|Chrome|Firefox)",\n                             array_concat(DiscoveryTypes, dynamic(["File Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(dir\\s|ls\\s|find\\s|grep\\s|type\\s|cat\\s|more\\s|bookmarks|Chrome|Firefox)",\n                           max_of(MaxDiscoverySeverity, 2),\n                           MaxDiscoverySeverity\n                       )\n    // Credential Discovery\n    | extend\n        DiscoveryTypes = case(\n                             ProcessCommandLine matches regex @"(?i)(vault|keychain|passwd|shadow)",\n                             array_concat(DiscoveryTypes, dynamic(["Credential Discovery"])),\n                             DiscoveryTypes\n                         ),\n        MaxDiscoverySeverity = case(\n                           ProcessCommandLine matches regex @"(?i)(vault|keychain|passwd|shadow)",\n                           max_of(MaxDiscoverySeverity, 4),\n                           MaxDiscoverySeverity\n                       )\n    | extend\n        ParentProcessName = coalesce(InitiatingProcessFileName, "Unknown"),\n        ProcessTree = strcat(coalesce(InitiatingProcessParentFileName, "Unknown"), " -> ", coalesce(InitiatingProcessFileName, "Unknown"), " -> ", FileName)\n    | summarize\n        TotalCommands = count(),\n        Commands = make_set(ProcessCommandLine, 50),\n        UniqueCommands = dcount(ProcessCommandLine),\n        AllDiscoveryTypes = make_set(DiscoveryTypes),\n        UniqueDiscoveryTypes = array_length(make_set(DiscoveryTypes)),\n        NewCommands = make_set(NormalizedCommand, 20),\n        NewCommandCount = dcount(NormalizedCommand),\n        MaxSeverity = max(MaxDiscoverySeverity),\n        ProcessTrees = make_set(ProcessTree, 10)\n        by DeviceId, DeviceName, AccountName, AccountDomain, bin(TimeGenerated, 15m);\n// Step 4: Join baseline with current activity\ncurrentActivity\n| join kind=inner (statsPerUserDevice) on DeviceId, AccountName, AccountDomain\n| extend DynamicMinCommandCount = toint(AvgCommandsPerHour + 2 * StdDevCommandsPerHour)\n| extend IsUnusualVolume = TotalCommands > DynamicMinCommandCount\n| where IsUnusualVolume or UniqueDiscoveryTypes >= 2\n| extend\n    RiskScore = (NewCommandCount * 10) + (UniqueDiscoveryTypes * 15) +\n    (MaxSeverity * 5) + iff(array_length(ProcessTrees) > 5, 10, 0)\n| extend\n    AlertSeverity = case(\n                    UniqueDiscoveryTypes >= 3 and MaxSeverity >= 3,\n                    "Critical",\n                    MaxSeverity >= 4,\n                    "Critical",\n                    UniqueDiscoveryTypes >= 3,\n                    "High",\n                    NewCommandCount >= 3 or UniqueDiscoveryTypes >= 2,\n                    "Medium",\n                    "Low"\n                )\n| where AlertSeverity in ("Critical", "High", "Medium")\n| extend\n    AlertTitle = strcat(\n                 "Multi-Stage Discovery: ",\n                 iff(UniqueDiscoveryTypes > 0, strcat(UniqueDiscoveryTypes, " discovery types detected"), ""),\n                 iff(NewCommandCount > 0 and UniqueDiscoveryTypes > 0, ", ", ""),\n                 iff(NewCommandCount > 0, strcat(NewCommandCount, " new commands"), "")\n             )\n| extend\n    DiscoveryVelocity = TotalCommands / 60.0\n| project\n    StartTime = TimeGenerated,\n    DeviceId,\n    DeviceName,\n    AccountName,\n    AccountDomain,\n    AlertTitle,\n    AlertSeverity,\n    RiskScore,\n    UniqueCommands,\n    TotalCommands,\n    DiscoveryVelocity,\n    UniqueDiscoveryTypes,\n    AllDiscoveryTypes,\n    NewCommands,\n    ProcessTrees\n| where AlertSeverity has_any (\'High\', \'Critical\') //reduce falsse positives\n| where not(AccountName has_any(\'system\', \'root\')) //reduce false positives\n| where DiscoveryVelocity > 1.0 //reduce false positives\n| where UniqueDiscoveryTypes >= 3  //reduce false positives\n| order by RiskScore desc, StartTime desc\n| take 100'
    queryFrequency: 'PT1H'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'Discovery'
    ]
    techniques: [
      'T0840'
      'T1007'
      'T1082'
      'T1087'
      'T1135'
      'T1217'
      'T1420'
    ]
    subTechniques: []
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
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
            columnName: 'AccountName'
          }
        ]
      }
      {
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'CommandLine'
            columnName: 'UniqueCommands'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
