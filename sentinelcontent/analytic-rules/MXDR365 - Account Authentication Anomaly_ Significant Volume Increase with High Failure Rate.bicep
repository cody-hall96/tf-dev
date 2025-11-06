param workspace string

resource workspace_Microsoft_SecurityInsights_f7056935_8bff_4bfb_808f_0fb88ed6073f 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/f7056935-8bff-4bfb-808f-0fb88ed6073f'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - Account Authentication Anomaly: Significant Volume Increase with High Failure Rate'
    description: 'This detection rule identifies abnormal authentication patterns by analyzing Windows Event Logs (Event IDs 4624 and 4625) and comparing user account login activity from the past 24 hours against a 7-day historical baseline (days 2-8). It triggers when an account shows a significant increase in overall authentication attempts (>20%) compared to its baseline. The rule specifically filters for high-severity alerts where the failure ratio exceeds 10%, focusing analyst attention on the most critical potential compromise indicators. This combination effectively targets brute force attacks, password spraying attempts, and compromised credentials while filtering out normal variations. The rule establishes personalized baselines for each account, reducing false positives while highlighting genuine anomalies that warrant immediate investigation. It provides comprehensive metrics including current and historical authentication counts, percentage increases, and failure ratios to help analysts quickly assess the context of potential threats.'
    severity: 'Medium'
    enabled: true
    query: '// PURPOSE:\n// This query detects abnormal increases in authentication activity (both successful and failed logins)\n// by comparing recent user account activity against historical baselines.\n// \n// USE CASES:\n// - Detect potential account compromises or brute force attacks\n// - Identify unusual authentication patterns that might indicate lateral movement\n// - Monitor for credential stuffing or password spray attacks across multiple accounts\n// - Establish behavioral baselines for user authentication patterns\n//\n// OVERVIEW:\n// The query compares login activity (Events 4624 & 4625) over the last 24 hours\n// against the average daily activity from the previous 7 days (days 2-8).\n// It triggers alerts when the increase exceeds a configurable threshold (default 20%).\n//\n// Define the time windows and threshold for comparison\nlet timeFrame = 24h;         //24 Recent period to evaluate (last 24 hours)\nlet lookbackStart = 8d;      //8 Start of historical lookback period (8 days ago)\nlet lookbackEnd = 1d;        //1 End of historical lookback period (1 day ago)\nlet alertThreshold = 20;     //20 Alert threshold percentage (20% increase)\nlet minEventCount = 5;       //5 Minimum number of events to consider (reduces noise)\n//\n// Calculate authentication metrics for the most recent 24-hour period\nlet currentPeriodLogins = SecurityEvent\n    | where TimeGenerated > ago(timeFrame)\n    // Focus on Windows authentication events (success and failure)\n    | where EventID in (4624, 4625) \n    // Use the non-nested Account field directly\n    | where isnotempty(Account) and Account != ""\n    // Calculate metrics for each user account\n    | summarize \n        // Count successful logins (Event 4624)\n        CurrentSuccessCount = countif(EventID == 4624),\n        // Count failed logins (Event 4625)\n        CurrentFailCount = countif(EventID == 4625),\n        // Count total authentication attempts\n        CurrentTotalCount = count() \n        by Account\n    | project Account, CurrentSuccessCount, CurrentFailCount, CurrentTotalCount;\n//\n// Calculate average daily authentication metrics from the previous 7 days\nlet historicalPeriodLogins = SecurityEvent\n    // Look at data between 1 day ago and 8 days ago (7 day window)\n    | where TimeGenerated between (ago(lookbackStart) .. ago(lookbackEnd))\n    // Focus on Windows authentication events (success and failure)\n    | where EventID in (4624, 4625)\n    // Use the non-nested Account field directly\n    | where isnotempty(Account) and Account != ""\n    // Calculate historical metrics for each user account\n    | summarize \n        // Count historical successful logins (Event 4624)\n        HistoricalSuccessCount = countif(EventID == 4624),\n        // Count historical failed logins (Event 4625)\n        HistoricalFailCount = countif(EventID == 4625),\n        // Count historical total authentication attempts\n        HistoricalTotalCount = count() \n        by Account\n    // Convert 7-day totals to daily averages\n    | extend \n        // Average daily successful logins\n        DailyAvgSuccessful = HistoricalSuccessCount / 7,\n        // Average daily failed logins\n        DailyAvgFailed = HistoricalFailCount / 7,\n        // Average daily total authentication attempts\n        DailyAvgTotal = HistoricalTotalCount / 7\n    | project Account, DailyAvgSuccessful, DailyAvgFailed, DailyAvgTotal;\n//\n// Join current and historical data to identify significant changes\ncurrentPeriodLogins\n| join kind=inner historicalPeriodLogins on Account\n| extend \n    // Calculate percentage increase in total authentication attempts\n    // Formula: ((Current - Historical) / Historical) * 100\n    TotalPercentIncrease = ((CurrentTotalCount - DailyAvgTotal) / DailyAvgTotal) * 100.0,\n    //\n    // Calculate percentage increase in failed logins\n    // Use special handling for cases with zero historical failures\n    // Set to 999% if there were no historical failures but there are current failures\n    FailedPercentIncrease = iff(\n                            DailyAvgFailed > 0, \n                            ((CurrentFailCount - DailyAvgFailed) / DailyAvgFailed) * 100.0, \n                            iff(CurrentFailCount > 0, 999.0, 0.0)\n                        )\n//\n// ALERT CRITERIA:\n// 1. Total authentication activity increased by more than the threshold percentage\n| where TotalPercentIncrease >= alertThreshold\n// 2. Ensure sufficient activity volume to avoid noise from rarely-used accounts\n| where CurrentTotalCount > minEventCount\n//\n// ALERT OUTPUT:\n| project \n    // User identity information\n    Account,\n    //\n    // Current period metrics (last 24 hours)\n    CurrentSuccessCount,\n    CurrentFailCount, \n    CurrentTotalCount,\n    //\n    // Historical baseline metrics (daily averages)\n    DailyAvgSuccessful,\n    DailyAvgFailed,\n    DailyAvgTotal,\n    //\n    // Analysis metrics\n    TotalPercentIncrease = round(TotalPercentIncrease, 2),\n    FailedPercentIncrease = round(FailedPercentIncrease, 2),\n    // Calculate what percentage of current login attempts are failures\n    FailRatio = round((CurrentFailCount * 1.0 / CurrentTotalCount) * 100, 2),\n    //\n    // Alert description for SOC analysts\n    AlertReason = strcat(\n                  "Authentication anomaly detected: Login activity for user increased by ", \n                  round(TotalPercentIncrease, 2), \n                  "% compared to historical baseline. ",\n                  iff(\n    FailedPercentIncrease > alertThreshold,\n    strcat("Failed login increase: ", round(FailedPercentIncrease, 2), "%."),\n    ""\n)\n              )\n//\n// Sort results by most significant anomalies first\n| order by TotalPercentIncrease desc, CurrentTotalCount desc\n//\n// Add timestamp for alert creation time\n| extend AlertSeverity = iff(\n                             FailedPercentIncrease > alertThreshold, \n                             "High", \n                             "Medium"\n                         )\n| where AlertSeverity has \'High\'\n| where FailRatio > 10\n\n'
    queryFrequency: 'P1D'
    queryPeriod: 'P8D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    startTimeUtc: null
    tactics: [
      'InitialAccess'
      'Persistence'
      'PrivilegeEscalation'
      'CredentialAccess'
      'LateralMovement'
    ]
    techniques: [
      'T1566'
      'T1078'
      'T0822'
      'T0859'
      'T1110'
      'T1555'
      'T1557'
      'T0886'
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
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'Account'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
