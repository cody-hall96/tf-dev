param workspace string
param automationRuleId string = 'd1b41acd-faa7-477e-acf7-49018c4a361a'
param displayName string = 'MXDR365 - Suppress FP Incidents - 31 to 40'

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
                    'MXDR365 -Anomolous Single Factor Signin'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'MXDR365 -Rare subscription-level operations in Azure'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'Granted Mailbox Permissions'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'DLP policy'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'A network session Destination address 35.190.39.113 matched an IoC.'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'MXDR365 -Explicit MFA Deny (User reports Fraud)'
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
