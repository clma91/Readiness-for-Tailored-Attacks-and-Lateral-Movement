Function GetEventLogsAndExport([String] $ExportPath){
    $LogNames = @("System", "Security")
    $ExportPathCSV = "$ExportPath\eventlogs.csv"

    Write-Host "Collecting EventLogs"
    foreach($Log in $LogNames)
    {
       $EventLogs += Get-EventLog -LogName $Log
    }
    Write-Host "Done collecting"

    $EventLogs | Select-Object EventID -Unique |Export-CSV $ExportPathCSV -NoTypeInfo -Encoding UTF8 
}
Function GetTargetWindowsLogs {
    [xml]$TargetList = Get-Content ("$PSScriptRoot\..\Config\event_log_list.xml")
    $WindowsLogs = @()
    foreach ($Log in $TargetList.Logs.WindowsLogs.ChildNodes) {
        $WindowsLogs += $Log.InnerXML
    }
    return $WindowsLogs
}
Function GetTargetAppAndServLogs {
    [xml]$TargetList = Get-Content ("$PSScriptRoot\..\Config\event_log_list.xml")
    $AppAndServLogs = @()
    foreach ($Log in $TargetList.Logs.AppAndServLogs.ChildNodes) {
        $AppAndServLogs += $Log.InnerXML
    }
    return $AppAndServLogs
}
Function GetApplicationAndServiceLogs([String] $ExportPath) {
    $IdsForTaskScheduler = (106, 200, 129, 201, 102)
    $IdsForWindowsRemoteManagement = (6, 169)
    $IdsForLocalSessionManager = (21, 24)
    $ExportPathCSV = "$ExportPath\appandservlogs.csv"

    $AppAndServLogs += '"EventID"' 
    Write-Host "Checking TaskScheduler-Logs"
    foreach($Id in $IdsForTaskScheduler){
        if(wevtutil qe Microsoft-Windows-TaskScheduler/Operational /q:"*[System[(EventID="$Id")]]" /uni:false /f:text){
            $AppAndServLogs += '"' + $Id + '"'
        }
    }
    Write-Host "Checking WinRM-Logs"
    foreach($Id in $IdsForWindowsRemoteManagement){
        if(wevtutil qe Microsoft-Windows-WinRM/Operational /q:"*[System[(EventID="$Id")]]" /uni:false /f:text){
            $AppAndServLogs += '"' + $Id + '"'
        }
    }
    Write-Host "Checking LocalSessionManager-Logs"
    foreach($Id in $IdsForLocalSessionManager){ 
        if(wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /q:"*[System[(EventID="$Id")]]" /uni:false /f:text){
            $AppAndServLogs += '"' + $Id + '"'
        }
    }

    $AppAndServLogs | Out-File -FilePath $ExportPathCSV
}

Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $StartElement, [String] $Value) {
    $XmlWriter.WriteStartElement($StartElement)
    $XmlWriter.WriteValue($Value)
    $XmlWriter.WriteEndElement()
}

Function ImportCompareExport([String] $ImportPath, [String] $ExportPath){
    $EventLogIdsToCheck = GetTargetWindowsLogs
    $AppAndServIdsToCheck = GetTargetAppAndServLogs
    $ResultXML = "$ExportPath\result_event_logs.xml"
    $ImportEventLogs = "$ImportPath\eventlogs.csv"
    $ImportAppAndServLogs = "$ImportPath\appandservlogs.csv"
    
    if (-not [System.IO.File]::Exists($ImportEventLogs)) {
        Write-Host "File $ImportEventLogs does not exist!" -ForegroundColor Red
        return $false
    }
    if (-not [System.IO.File]::Exists($ImportAppAndServLogs)) {
        Write-Host "File $ImportAppAndServLogs does not exist!" -ForegroundColor Red
        return $false
    }        

    $Encoding = New-Object System.Text.UTF8Encoding($false)
    $XmlWriter = New-Object System.XMl.XmlTextWriter($ResultXML, $Encoding)
    $MyEventLogs = Import-Csv $ImportEventLogs -Encoding UTF8

    Write-Host "Comparing found EventLogs to Checklist"
    
    $XmlWriter.Formatting = "Indented"
    $XmlWriter.Indentation = 1
    $XmlWriter.IndentChar = "`t"
    $XmlWriter.WriteStartDocument()
    $XmlWriter.WriteStartElement("Logs")
    $XmlWriter.WriteStartElement("EventLogsID")

    foreach($Id in $EventLogIdsToCheck){
        if($MyEventLogs | Where-Object {$_.EventID -eq $Id}){ 
            WriteXMLElement $XmlWriter ("EventID" +$Id) "present"
        } else {
            WriteXMLElement $XmlWriter ("EventID" +$Id) "missing"
        }
    }
    $XmlWriter.WriteEndElement()
    
    $MyAppAndServLogs = Import-Csv $ImportAppAndServLogs -Encoding UTF8 
    Write-Host "Comparing found AppAndServLogs"
    $XmlWriter.WriteStartElement("AppAndServID")

    foreach($Id in $AppAndServIdsToCheck){
        if($MyAppAndServLogs | Where-Object {$_.EventID -eq $Id}){
            WriteXMLElement $XmlWriter ("EventID" +$Id) "present"
        } else{
            WriteXMLElement $XmlWriter ("EventID" +$Id) "missing"
        }
    }

    Write-Host "Exporting results into XML"
    $XmlWriter.WriteEndElement()
    $XmlWriter.WriteEndDocument()
    $XmlWriter.Flush()
    $XmlWriter.Close()
    
    if ($ImportPath -eq $ExportPath) {
        Remove-Item $ImportEventLogs
        Remove-Item $ImportAppAndServLogs
    }
    return $true
}

Export-ModuleMember -Function GetEventLogsAndExport, ImportCompareExport, GetApplicationAndServiceLogs



