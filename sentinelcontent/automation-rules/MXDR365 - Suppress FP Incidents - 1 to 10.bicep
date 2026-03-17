param workspace string
param automationRuleId string = 'ae6076bd-b08b-45fb-bdea-2edfa8928a77'
param displayName string = 'MXDR365 - Suppress FP Incidents - 1 to 10'

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
                    'Connection to a custom network indicator'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'MXDR365 -Suspicious Resource deployment'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'MXDR365 -Attempts to sign in to disabled accounts involving multiple users'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    '(BETA) MXDR365 - Impair Defenses: Safe Boot Mode'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'Tenant Allow/Block List entry is about to expire'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'MXDR365 -TI map Domain entity to DeviceNetworkEvents'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Contains'
                  propertyValues: [
                    'Purview IRM'
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
        order: 2
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
        order: 3
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: null
          status: 'Closed'
          classification: 'BenignPositive'
          classificationReason: 'SuspiciousButExpected'
          classificationComment: 'After investigation this Incident was deemed to be benign but suspicious. The alerting query is accurate, but the investigation has led to a 100% false positive ratio over the last 30 days.'
          owner: null
          labels: null
        }
      }
    ]
  }
}
