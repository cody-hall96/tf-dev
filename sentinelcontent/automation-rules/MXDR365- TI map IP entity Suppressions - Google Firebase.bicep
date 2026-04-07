param workspace string
param automationRuleId string = '7a19d962-7d62-41e6-a64c-8f9c5cd79f92'
param displayName string = 'MXDR365- TI map IP entity Suppressions - Google Firebase'

param ownerObjectId string = '752150df-af7f-4380-adcf-0c42092cd637'
param ownerEmail string = 'mxdrautomation@mxdr365.com'
param ownerAssignedTo string = 'MXDR Automation'
param ownerUserPrincipalName string = 'mxdrautomation@mxdr365.com'

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
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentTitle'
            operator: 'Equals'
            propertyValues: [
              'MXDR365- TI map IP entity to Network Session Events (ASIM Network Session schema)'
            ]
          }
        }
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IPAddress'
            operator: 'Equals'
            propertyValues: [
              '35.190.39.113'
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
            email: ownerEmail
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
          status: 'Closed'
          classification: 'BenignPositive'
          classificationReason: 'SuspiciousButExpected'
          classificationComment: 'This IP Address is owned by Google Firebase and is known to trigger incorrect incidents. '
          owner: null
          labels: null
        }
      }
    ]
  }
}
