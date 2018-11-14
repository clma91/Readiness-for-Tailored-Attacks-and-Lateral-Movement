Import-Module .\GetAndCompareLogs.psm1 -Force
# $importEventLogs = $PSScriptRoot + "\myeventlogs.csv"
# $importAppAndServLogs =  $PSScriptRoot + "\myappandservlogs.csv"


GetEventLogsAndExport
GetApplicationAndServiceLogs
ImportCompareExport
