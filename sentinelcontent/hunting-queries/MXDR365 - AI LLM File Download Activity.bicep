param workspace string

resource savedSearch 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  name: '${workspace}/ea839474-bd81-46a0-8d96-84cf52077c47'
  properties: {
    displayName: 'MXDR365 - AI LLM File Download Activity'
    category: 'Hunting Queries'
    query: '''
let suspiciousSources = dynamic(["chatgpt", "claude", "grok", "gemini"]);
DeviceFileEvents
| extend
    lowerOriginUrl = tolower(FileOriginUrl),
    lowerReferrerUrl = tolower(FileOriginReferrerUrl),
    lowerAccountName = tolower(InitiatingProcessAccountName)
| where (
    suspiciousSources has_any(lowerOriginUrl, lowerReferrerUrl)
    and (FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr" or FileName endswith ".bat" or FileName endswith ".ps1")
)
or lowerAccountName contains "admin"
| extend
    FileOrigin = coalesce(FileOriginUrl, FileOriginReferrerUrl)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    FileOrigin,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    ReportId
| order by Timestamp desc
| extend Host_0_HostName = DeviceName
| extend File_0_Name = FileName
'''
    version: 2
    tags: [
      {
        name: 'tactics'
        value: 'InitialAccess,Execution'
      }
      {
        name: 'createdBy'
        value: 'dpaulson@mxdr365.com'
      }
      {
        name: 'techniques'
        value: 'T1660,T0863,T1059'
      }
      {
        name: 'createdTimeUtc'
        value: '10/07/2025 15:44:16'
      }
    ]
  }
}
