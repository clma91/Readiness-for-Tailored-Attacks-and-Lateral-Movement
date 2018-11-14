function GetEventLogsAndExport($logNames){
    $eventLogs = New-Object System.Collections.ArrayList
    $exportPath = $PSScriptRoot + "\myeventlogs.csv"
    Write-Host Collecting EventLogs
    $StartMs = (Get-Date).Ticks
    foreach($log in $logNames)
    {
       $eventLogs += Get-EventLog -LogName $log
    }
    $EndMs = (Get-Date).Ticks
    Write-Host It took $($EndMs - $StartMs) ticks, or $(($EndMs - $StartMs) /10000000) secs. to get the EventLogs
    Write-Host Done collecting

    $eventLogs | Select EventID -Unique |Export-CSV $exportPath -NoTypeInfo -Encoding UTF8 
    Write-Host Done exporting to $exportPath 
}
function GetApplicationAndServiceLogs {
    $idsForTaskScheduler = (106, 200, 129, 201, 102)
    $idsForWindowsRemoteManagement = (6, 169)
    $idsForLocalSessionManager = (21, 24)
    $exportPath = $PSScriptRoot + "\myappandservlogs.csv"

    $appAndServLogs += '"EventID"' 
    
    foreach($id in $idsForTaskScheduler){
    if(wevtutil qe Microsoft-Windows-TaskScheduler/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
        $appAndServLogs += '"' + $id + '"'
         }
    }
    
    foreach($id in $idsForWindowsRemoteManagement){
        if(wevtutil qe Microsoft-Windows-WinRM/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
            $appAndServLogs += '"' + $id + '"'
            }
    }
    
        foreach($id in $idsForLocalSessionManager){ 
            if(wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
                $appAndServLogs += '"' + $id + '"'
            }
        }

    $appAndServLogs | Out-File -FilePath $exportPath
}

Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $startElement, [String] $value) {
    $xmlWriter.WriteStartElement($startElement)
    $xmlWriter.WriteValue($value)
    $xmlWriter.WriteEndElement()
}

function ImportCompareExport($eventLogIdsToCheck,  $appAndServIdsToCheck){
    $importEventLogs = $PSScriptRoot + "\myeventlogs.csv"
    $resultXML = $PSScriptRoot + "\resultOfEventLogs.xml"
    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null) 
    
    $myEventLogs = Import-Csv $importEventLogs -Encoding UTF8

    Write-Host Comparing Found EventLogs to Checklist
    
    $xmlWriter.Formatting = "Indented"
    $xmlWriter.Indentation = 1
    $xmlWriter.IndentChar = "`t"
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteStartElement("Logs")
    $xmlWriter.WriteStartElement("EventLogsID")

    foreach($id in $eventLogIdsToCheck){
        if($myEventLogs | where {$_.EventID -eq $id}){ 
            WriteXMLElement $xmlWriter ("EventID" +$id) "present"
        } else {
            WriteXMLElement $xmlWriter ("EventID" +$id) "missing"
        }
    }
    $xmlWriter.WriteEndElement()

    $importAppAndServLogs =  $PSScriptRoot + "\myappandservlogs.csv"
    $myAppAndServLogs = Import-Csv $importAppAndServLogs -Encoding UTF8 

    Write-Host Comparing Found AppAndServLogs
    $xmlWriter.WriteStartElement("AppAndServID")

    foreach($id in $appAndServIdsToCheck){
        if($myAppAndServLogs | where {$_.EventID -eq $id}){
            WriteXMLElement $xmlWriter ("EventID" +$id) "present"
        } else{
            WriteXMLElement $xmlWriter ("EventID" +$id) "missing"
        }
    }
    Write-Host Done comparing

    Write-Host Exporting XML
    $xmlWriter.WriteEndElement()
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()
    
    Write-Host Done!

    Remove-Item $importEventLogs
    Remove-Item $importAppAndServLogs
}

Export-ModuleMember -Function GetEventLogsAndExport, ImportCompareExport, GetApplicationAndServiceLogs



