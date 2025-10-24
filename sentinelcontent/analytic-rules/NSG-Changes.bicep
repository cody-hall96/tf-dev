param workspace string

resource workspace_Microsoft_SecurityInsights_74a23c80_4ac7_4b86_a399_9a1fafc90b23 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/74a23c80-4ac7-4b86-a399-9a1fafc90b23'
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - NSG Changes2'
    description: 'This query looks at changes made to network security groups in Azure, showing the resource that was changed and who made the change'
    severity: 'Medium'
    enabled: true
    query: 'AzureActivity\n| where parse_json(Authorization).action == "Microsoft.Network/networkSecurityGroups/securityRules/write" and ActivityStatus == "Succeeded"\n| distinct Resource, Caller\n| extend AccountCustomEntity = Caller\n| extend URLCustomEntity = Resource'
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 5
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
            columnName: 'AccountCustomEntity'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'Caller'
          }
        ]
      }
      {
        entityType: 'URL'
        fieldMappings: [
          {
            identifier: 'Url'
            columnName: 'URLCustomEntity'
          }
        ]
      }
    ]
    sentinelEntitiesMappings: null
    templateVersion: null
  }
}
