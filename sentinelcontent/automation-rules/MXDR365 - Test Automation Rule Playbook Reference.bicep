param workspace string
param automationRuleId string
param automationRuleDisplayName string
param playbookLogicAppResourceId string
param playbookTenantId string

resource automationRule 'Microsoft.OperationalInsights/workspaces/providers/automationRules@2024-04-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/${automationRuleId}'
  properties: {
    displayName: automationRuleDisplayName
    order: 1
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Updated'
      conditions: [
        {
          conditionType: 'Boolean'
          conditionProperties: {
            operator: 'Or'
            innerConditions: [
              {
                conditionType: 'PropertyArrayChanged'
                conditionProperties: {
                  arrayType: 'Comments'
                  changeType: 'Added'
                }
              }
              {
                conditionType: 'PropertyChanged'
                conditionProperties: {
                  propertyName: 'IncidentOwner'
                  operator: null
                  changeType: null
                }
              }
              {
                conditionType: 'PropertyArrayChanged'
                conditionProperties: {
                  arrayType: 'Alerts'
                  changeType: 'Added'
                }
              }
              {
                conditionType: 'PropertyArrayChanged'
                conditionProperties: {
                  arrayType: 'Labels'
                  changeType: 'Added'
                }
              }
              {
                conditionType: 'PropertyChanged'
                conditionProperties: {
                  propertyName: 'IncidentSeverity'
                  operator: null
                  changeType: null
                }
              }
              {
                conditionType: 'PropertyArrayChanged'
                conditionProperties: {
                  arrayType: 'Tactics'
                  changeType: 'Added'
                }
              }
              {
                conditionType: 'PropertyChanged'
                conditionProperties: {
                  propertyName: 'IncidentStatus'
                  operator: null
                  changeType: null
                }
              }
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: playbookLogicAppResourceId
          tenantId: playbookTenantId
        }
      }
    ]
  }
}
