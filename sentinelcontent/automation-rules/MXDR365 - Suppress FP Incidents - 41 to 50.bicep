param workspace string
param automationRuleId string = '696432db-0618-4fa7-954e-5ab43ede1a02'
param displayName string = 'MXDR365 - Suppress FP Incidents - 41 to 50'

param ownerObjectId string = '2487425e-4a3a-41fc-bae3-f6aa87e8f733'
param ownerAssignedTo string = 'MXDR365 Automation Account'
param ownerUserPrincipalName string = 'MXDR365AutomationAccount@mxdr365.com'

resource automationRule 'Microsoft.OperationalInsights/workspaces/providers/automationRules@2024-04-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/${automationRuleId}'
  properties: {
    displayName: displayName
    order: 2
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Boolean'
          conditionProperties: {
            operator: 'Or'
            innerConditions: [
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'Unsanctioned cloud app access was blocked'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'Open Wi-Fi connection'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'Windows Binaries Executed from Non-Default Directory'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'Multiple failed user log on attempts to an app'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Contains'
                  propertyValues: [
                    'junk'
                  ]
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
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: null
          status: null
          classification: null
          classificationReason: null
          classificationComment: null
          owner: null
          labels: [
            {
              labelName: 'Suppressed'
              labelType: 'User'
            }
          ]
        }
      }
      {
        order: 2
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: null
          status: null
          classification: null
          classificationReason: null
          classificationComment: null
          owner: {
            objectId: ownerObjectId
            email: null
            assignedTo: ownerAssignedTo
            userPrincipalName: ownerUserPrincipalName
          }
          labels: null
        }
      }
      {
        order: 3
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: null
          status: 'Closed'
          classification: 'BenignPositive'
          classificationReason: 'SuspiciousButExpected'
          classificationComment: 'After investigation this Incident was deemed to be benign but suspicious. The alerting query is accurate, but the investigation has led to an above 99.5% false positive ratio over the last 30 days.'
          owner: null
          labels: null
        }
      }
    ]
  }
}
