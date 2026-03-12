param workbookSourceId string
param workbookId string
param serializedData string

var workbookDisplayName = 'Patriot MXDR SOC Performance'
var workbookType = 'sentinel'

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: resourceGroup().location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    category: workbookType
    sourceId: workbookSourceId
    version: '1.0'
    serializedData: serializedData
  }
}

output workbookResourceId string = workbook.id
