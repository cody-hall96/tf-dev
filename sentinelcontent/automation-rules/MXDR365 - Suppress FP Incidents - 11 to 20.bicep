param workspace string
param automationRuleId string = 'd1e62d21-ea3f-41ab-96f8-d1e493696e8a'
param displayName string = 'MXDR365 - Suppress FP Incidents - 11 to 20'

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
                  operator: 'Equals'
                  propertyValues: [
                    'CC_Inappropriate Content'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'MXDR365 - Remote Services: SMB/Windows Admin Shares'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'Administrative action submitted by an Administrator'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'Remote code execution attempt'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'MXDR365 -New executable via Office FileUploaded Operation'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'MXDR365 - WMIC Antivirus Discovery'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'MXDR365 - Command Line User Addition'
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
