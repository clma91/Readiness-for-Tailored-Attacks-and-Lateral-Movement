Set-Variable -Name ApplicationLog -Value "Application"
Set-Variable -Name SystemLog -Value "System"
Set-Variable -Name SecurityLog -Value "Security"
Set-Variable -Name ExportFolder -Value  (Resolve-Path .\).Path #current Path
Set-Variable -Name CheckApplicationLogIDs -Value @(6, 21, 24, 102, 106, 129, 169, 200, 201, 20001) #according to JPCERT
Set-Variable -Name CheckSystemLogIDs -Value @(7036, 7045, 20001)#according to JPCERT
Set-Variable -Name CheckSecurityLogIDs -Value @(104, 4624, 4634, 4648, 4656, 4658, 4660, 4661, 4663, 4672, 4673, 4688, 4689, 4690, 4720, 4726, 4728, 4729, 4768, 4769, 4946, 5140, 5142, 5144, 5145, 5154, 5156, 8222)#according to JPCERT

$now=get-date
$ExportFile=$ExportFolder + "\eventids" + $now.ToString("yyyy-MM-dd---hh-mm-ss") + ".txt"
$events = New-Object System.Collections.ArrayList
function FindEventlogsByLog {
    $events.add($args[1] + ": ")
    foreach($eventid in $args[0])
    {
         if(get-eventlog -LogName $args[1] -InstanceId $eventid -ErrorAction SilentlyContinue -InformationAction SilentlyContinue){
            $events.add("EventID: " + $eventid)
        }
    }   
    $events.add("")
}

FindEventlogsByLog $CheckApplicationLogIDs $ApplicationLog
FindEventlogsByLog $CheckSystemLogIDs $SystemLog
FindEventlogsByLog $CheckSecurityLogIDs $SecurityLog

Write-Host Exporting to $ExportFile
$events | Out-File -FilePath $ExportFile
Write-Host Done!