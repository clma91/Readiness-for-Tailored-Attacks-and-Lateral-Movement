Remove-Module GetAndCompareEvents
Import-Module .\GetAndCompareEvents.psm1

$LogNames = @("System", "Security")
$currentFolder = (Resolve-Path .\).Path #current Path
$eventLogIdsToCheck = (6, 21, 24, 102, 104, 106, 129, 169, 200, 201, 4624, 4634, 4648, 4656, 4658, 4660, 4661, 4663, 4672, 4673, 4688, 4689, 4690, 4720, 4726, 4728, 4729, 4768,4769, 4946, 5140, 5142, 5144, 5145, 5154, 5156, 7036, 7045, 8222, 20001)
$appAndServIdsToCheck = (106, 200, 129, 201, 102, 6, 169, 21, 24)
$idsForTaskScheduler = ("106", "200", "129", "201", "102")
$idsForWindowsRemoteManagement = ("6", "169")
$idsForLocalSessionManager = ("21", "24")


$exportEventLogsIntoCSV=$currentFolder + "\myeventlogs.csv"
$exportApplicationAndServiceLogsIntoCSV = $currentFolder + "\myapplicationandsiencelogs.csv"

$eventLogs = New-Object System.Collections.ArrayList
$appAndServLogs = New-Object System.Collections.ArrayList

$myEventLogs = New-Object System.Object
$myAppAndServLogs = New-Object System.Object
$resultMyEvents = New-Object System.Collections.ArrayList

$resultXML = "resultOfEventLogs.xml"
$xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null)

GetEventLogsAndExport $LogNames $eventLogs $exportEventLogsIntoCSV
GetApplicationAndServiceLogs $appAndServLogs $idsForTaskScheduler $idsForWindowsRemoteManagement $idsForLocalSessionManager $exportApplicationAndServiceLogsIntoCSV
ImportCompareExport $exportEventLogsIntoCSV $myEventLogs $xmlWriter $eventLogIdsToCheck $exportApplicationAndServiceLogsIntoCSV $myAppAndServLogs $appAndServIdsToCheck
