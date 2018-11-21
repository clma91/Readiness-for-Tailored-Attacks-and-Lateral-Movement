function GetEventLogsAndExport($exportPath){
    $logNames = @("System", "Security")
    $exportPathCSV = $PSScriptRoot + "\myeventlogs.csv"
    if ($exportPath) {
        $exportPathCSV = $exportPath + "\myeventlogs.csv"
    }

    Write-Host Collecting EventLogs
    foreach($log in $logNames)
    {
       $eventLogs += Get-EventLog -LogName $log
    }
    $EndMs = (Get-Date).Ticks
    Write-Host "Done collecting"

    $eventLogs | Select EventID -Unique |Export-CSV $exportPathCSV -NoTypeInfo -Encoding UTF8 
}
function GetApplicationAndServiceLogs($exportPath) {
    $idsForTaskScheduler = (106, 200, 129, 201, 102)
    $idsForWindowsRemoteManagement = (6, 169)
    $idsForLocalSessionManager = (21, 24)
    $exportPathCSV = $PSScriptRoot + "\myappandservlogs.csv"
    if ($exportPath) {
        $exportPathCSV = $exportPath + "\myappandservlogs.csv"
    }

    $appAndServLogs += '"EventID"' 
    Write-Host "Checking TaskScheduler-Logs"
    foreach($id in $idsForTaskScheduler){
        if(wevtutil qe Microsoft-Windows-TaskScheduler/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
        $appAndServLogs += '"' + $id + '"'
        }
    }
    Write-Host "Checking WinRM-Logs"
    foreach($id in $idsForWindowsRemoteManagement){
        if(wevtutil qe Microsoft-Windows-WinRM/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
            $appAndServLogs += '"' + $id + '"'
        }
    }
    Write-Host "Checking LocalSessionManager-Logs"
        foreach($id in $idsForLocalSessionManager){ 
            if(wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
                $appAndServLogs += '"' + $id + '"'
            }
        }

    $appAndServLogs | Out-File -FilePath $exportPathCSV
}

Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $startElement, [String] $value) {
    $xmlWriter.WriteStartElement($startElement)
    $xmlWriter.WriteValue($value)
    $xmlWriter.WriteEndElement()
}

function ImportCompareExport($importPath, $exportPath){
    $eventLogIdsToCheck = (6, 21, 24, 102, 104, 106, 129, 169, 200, 201, 4624, 4634, 4648, 4656, 4658, 4660, 4661, 4663, 4672, 4673, 4688, 4689, 4690, 4720, 4726, 4728, 4729, 4768,4769, 4946, 5140, 5142, 5144, 5145, 5154, 5156, 7036, 7045, 8222, 20001)
    $appAndServIdsToCheck = (106, 200, 129, 201, 102, 6, 169, 21, 24)
    $isCurrentPath = $true

    $resultXML = $PSScriptRoot + "\resultOfEventLogs.xml"
    if ($exportPath) {
        $resultXML = $exportPath + "\resultOfEventLogs.xml"
    }

    $importEventLogs = $PSScriptRoot + "\myeventlogs.csv"
    $importAppAndServLogs = $PSScriptRoot + "\myappandservlogs.csv"
    if ($importPath) {
        $isCurrentPath = $false
        $importEventLogs = $importPath + "\myeventlogs.csv"
        $importAppAndServLogs = $importPath + "\myappandservlogs.csv"
        if (-not [System.IO.File]::Exists($importEventLogs)) {
            Write-Host "File $importEventLogs does not exist!" -ForegroundColor Red
            return
        }
        if (-not [System.IO.File]::Exists($importAppAndServLogs)) {
            Write-Host "File $importAppAndServLogs does not exist!" -ForegroundColor Red
            return
        }        
    }

    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null) 
    $myEventLogs = Import-Csv $importEventLogs -Encoding UTF8

    Write-Host "Comparing found EventLogs to Checklist"
    
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
    
    $myAppAndServLogs = Import-Csv $importAppAndServLogs -Encoding UTF8 
    Write-Host "Comparing found AppAndServLogs"
    $xmlWriter.WriteStartElement("AppAndServID")

    foreach($id in $appAndServIdsToCheck){
        if($myAppAndServLogs | where {$_.EventID -eq $id}){
            WriteXMLElement $xmlWriter ("EventID" +$id) "present"
        } else{
            WriteXMLElement $xmlWriter ("EventID" +$id) "missing"
        }
    }

    Write-Host "Exporting results into XML"
    $xmlWriter.WriteEndElement()
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()
    
    if ($isCurrentPath) {
        Remove-Item $importEventLogs
        Remove-Item $importAppAndServLogs
    }
}

Export-ModuleMember -Function GetEventLogsAndExport, ImportCompareExport, GetApplicationAndServiceLogs



