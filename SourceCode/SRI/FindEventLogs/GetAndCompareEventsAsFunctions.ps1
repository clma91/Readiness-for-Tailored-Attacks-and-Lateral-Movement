Remove-Module GetAndCompareEvents
Import-Module .\GetAndCompareEvents.psm1

# Set-Variable -Name LogNames -Value @("Application", "System", "Security")
# Set-Variable -Name ExportFolder -Value  (Resolve-Path .\).Path #current Path
# Set-Variable -Name idsToCheck (6, 21, 24, 102, 104, 106, 129, 169, 200, 201, 4624, 4634, 4648, 4656, 4658, 4660, 4661, 4663, 4672, 4673, 4688, 4689, 4690, 4720, 4726, 4728, 4729, 4768,4769, 4946, 5140, 5142, 5144, 5145, 5154, 5156, 7036, 7045, 8222, 20001)  

$LogNames = @("Application", "System", "Security")
$ExportFolder = (Resolve-Path .\).Path #current Path
$idsToCheck = (6, 21, 24, 102, 104, 106, 129, 169, 200, 201, 4624, 4634, 4648, 4656, 4658, 4660, 4661, 4663, 4672, 4673, 4688, 4689, 4690, 4720, 4726, 4728, 4729, 4768,4769, 4946, 5140, 5142, 5144, 5145, 5154, 5156, 7036, 7045, 8222, 20001)
$exportFile=$exportFolder + "\myevents.csv" 
$exportResultFile=$exportFolder + "\resultmyevents.txt" 
$events = New-Object System.Collections.ArrayList
$myEvents = New-Object System.Object
$resultMyEvents = New-Object System.Collections.ArrayList
$resultXML = "resultOfEventLogs.xml"
$xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null)

GetEventLogsAndExport $LogNames $events $exportFile
ImportCompareExport $exportFile $myEvents $xmlWriter $idsToCheck
