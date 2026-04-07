param workspace string
param automationRuleId string = '94eba111-f933-4484-b6f9-270928fbaee7'
param displayName string = 'MXDR365 - Suppress FP Incidents - 21 to 30'

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
                    'MXDR365 - Suspicious Execution Using Wsl'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'Files Copied to USB Drives on one endpoint'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'MXDR365 - Detecting EDR Killing Tool'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    '(BETA) MXDR365 - StrongAuthenticationUserDetails'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'Equals'
                  propertyValues: [
                    'Suspected SMB packet manipulation (CVE-2020-0796 exploitation) on one endpoint'
                  ]
                }
              }
              {
                conditionType: 'Property'
                conditionProperties: {
                  propertyName: 'IncidentTitle'
                  operator: 'StartsWith'
                  propertyValues: [
                    'MXDR365-Authentication Method Changed'
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
