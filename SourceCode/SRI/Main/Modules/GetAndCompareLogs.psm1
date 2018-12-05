function GetEventLogsAndExport([String] $exportPath){
    $logNames = @("System", "Security")
    $exportPathCSV = "$exportPath\eventlogs.csv"

    Write-Host "Collecting EventLogs"
    foreach($log in $logNames)
    {
       $eventLogs += Get-EventLog -LogName $log
    }
    Write-Host "Done collecting"

    $eventLogs | Select-Object EventID -Unique |Export-CSV $exportPathCSV -NoTypeInfo -Encoding UTF8 
}
Function GetTargetWindowsLogs {
    [xml]$targetList = Get-Content ("$PSScriptRoot\..\Config\event_log_list.xml")
    $windowsLogs = @()
    foreach ($log in $targetList.Logs.WindowsLogs.ChildNodes) {
        $windowsLogs += $log.InnerXML
    }
    return $windowsLogs
}
Function GetTargetAppAndServLogs {
    [xml]$targetList = Get-Content ("$PSScriptRoot\..\Config\event_log_list.xml")
    $appAndServLogs = @()
    foreach ($log in $targetList.Logs.AppAndServLogs.ChildNodes) {
        $appAndServLogs += $log.InnerXML
    }
    return $appAndServLogs
}
function GetApplicationAndServiceLogs([String] $exportPath) {
    $idsForTaskScheduler = (106, 200, 129, 201, 102)
    $idsForWindowsRemoteManagement = (6, 169)
    $idsForLocalSessionManager = (21, 24)
    $exportPathCSV = "$exportPath\appandservlogs.csv"

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

function ImportCompareExport([String] $importPath, [String] $exportPath){
    $eventLogIdsToCheck = GetTargetWindowsLogs
    $appAndServIdsToCheck = GetTargetAppAndServLogs
    $resultXML = "$exportPath\result_event_logs.xml"
    $importEventLogs = "$importPath\eventlogs.csv"
    $importAppAndServLogs = "$importPath\appandservlogs.csv"
    
    if (-not [System.IO.File]::Exists($importEventLogs)) {
        Write-Host "File $importEventLogs does not exist!" -ForegroundColor Red
        return $false
    }
    if (-not [System.IO.File]::Exists($importAppAndServLogs)) {
        Write-Host "File $importAppAndServLogs does not exist!" -ForegroundColor Red
        return $false
    }        

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML, $encoding)
    $myEventLogs = Import-Csv $importEventLogs -Encoding UTF8

    Write-Host "Comparing found EventLogs to Checklist"
    
    $xmlWriter.Formatting = "Indented"
    $xmlWriter.Indentation = 1
    $xmlWriter.IndentChar = "`t"
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteStartElement("Logs")
    $xmlWriter.WriteStartElement("EventLogsID")

    foreach($id in $eventLogIdsToCheck){
        if($myEventLogs | Where-Object {$_.EventID -eq $id}){ 
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
        if($myAppAndServLogs | Where-Object {$_.EventID -eq $id}){
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
    
    if ($importPath -eq $exportPath) {
        Remove-Item $importEventLogs
        Remove-Item $importAppAndServLogs
    }
    return $true
}

Export-ModuleMember -Function GetEventLogsAndExport, ImportCompareExport, GetApplicationAndServiceLogs



