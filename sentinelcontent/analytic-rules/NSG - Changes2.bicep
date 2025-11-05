@description('Name of the existing Log Analytics workspace')
param workspace string

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspace
}

resource nsgChangeRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  name: '74a23c80-4ac7-4b86-a399-9a1fafc90b23'
  scope: law
  kind: 'Scheduled'
  properties: {
    displayName: 'MXDR365 - NSG Changes2'
    description: 'This query looks at changes made to network security groups in Azure, showing the resource that was changed and who made the change.'
    severity: 'Medium'
    enabled: true
    query: '''
      AzureActivity
      | where parse_json(Authorization).action == "Microsoft.Network/networkSecurityGroups/securityRules/write" and ActivityStatus == "Succeeded"
      | distinct Resource, Caller
      | extend AccountCustomEntity = Caller
      | extend URLCustomEntity = Resource
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 5
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'DefenseEvasion'
    ]
    techniques: []
    subTechniques: []
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
  }
}
