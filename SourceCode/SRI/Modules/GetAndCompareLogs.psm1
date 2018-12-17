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

Function GetApplicationAndServiceLog ([Array] $Ids, [String] $LogName) {
    Write-Host "Checking $LogName-Logs"
    foreach($Id in $Ids){
        if(wevtutil qe Microsoft-Windows-$LogName/Operational /q:"*[System[(EventID="$Id")]]" /uni:false /f:text){
            $Result += '"' + $Id + '"'
        }
    }
    return $Result
}

Function GetApplicationAndServiceLogs([String] $ExportPath) {
    $IdsForTaskScheduler = (106, 200, 129, 201, 102)
    $IdsForWindowsRemoteManagement = (6, 169)
    $IdsForLocalSessionManager = (21, 24)
    $ExportPathCSV = "$ExportPath\appandservlogs.csv"

    $AppAndServLogs += '"EventID"' 
    $AppAndServLogs += GetApplicationAndServiceLog $IdsForTaskScheduler "TaskScheduler"
    $AppAndServLogs += GetApplicationAndServiceLog $IdsForWindowsRemoteManagement "WinRM"
    $AppAndServLogs += GetApplicationAndServiceLog $IdsForLocalSessionManager  "TerminalServices-LocalSessionManager"

    $AppAndServLogs | Out-File -FilePath $ExportPathCSV
}

Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $StartElement, [String] $Value) {
    $XmlWriter.WriteStartElement($StartElement)
    $XmlWriter.WriteValue($Value)
    $XmlWriter.WriteEndElement()
}

Function CompareEventsToTargetlist ($FoundEvents, $WindowsLogsToCheck, [String] $LogName) {
    Write-Host "Comparing found $LogName to Checklist"
    $XmlWriter.WriteStartElement($LogName)
    foreach($Id in $WindowsLogsToCheck){
        if($FoundEvents | Where-Object {$_.EventID -eq $Id}){ 
            WriteXMLElement $XmlWriter ("EventID" +$Id) "present"
        } else {
            WriteXMLElement $XmlWriter ("EventID" +$Id) "missing"
        }
    }
    $XmlWriter.WriteEndElement()
}

Function ImportCompareExport([String] $ImportPath, [String] $ExportPath){
    $ResultXML = "$ExportPath\result_event_logs.xml"
    $ImportEventLogs = "$ImportPath\eventlogs.csv"
    $ImportAppAndServLogs = "$ImportPath\appandservlogs.csv"
    $WindowsLogsToCheck = GetTargetWindowsLogs
    $AppAndServLogsToCheck = GetTargetAppAndServLogs
    
    if (-not [System.IO.File]::Exists($ImportEventLogs)) {
        Write-Host "File $ImportEventLogs does not exist!" -ForegroundColor Red
        return $false
    }
    if (-not [System.IO.File]::Exists($ImportAppAndServLogs)) {
        Write-Host "File $ImportAppAndServLogs does not exist!" -ForegroundColor Red
        return $false
    }        
    $FoundEventLogs = Import-Csv $ImportEventLogs -Encoding UTF8
    $FoundAppAndServLogs = Import-Csv $ImportAppAndServLogs -Encoding UTF8 
    $Encoding = New-Object System.Text.UTF8Encoding($false)
    $XmlWriter = New-Object System.XMl.XmlTextWriter($ResultXML, $Encoding)

    $XmlWriter.Formatting = "Indented"
    $XmlWriter.Indentation = 1
    $XmlWriter.IndentChar = "`t"
    $XmlWriter.WriteStartDocument()
    $XmlWriter.WriteStartElement("Logs")

    CompareEventsToTargetlist $FoundEventLogs $WindowsLogsToCheck "WindowsLogs"
    CompareEventsToTargetlist $FoundAppAndServLogs $AppAndServLogsToCheck "AppAndServLogs"

    Write-Host "Exporting results into XML"
    $XmlWriter.WriteEndDocument()
    $XmlWriter.Flush()
    $XmlWriter.Close()
    
    if ($ImportPath -eq $ExportPath) {
        Remove-Item $ImportEventLogs
        Remove-Item $ImportAppAndServLogs
    }
    return $true
}

Export-ModuleMember -Function GetEventLogsAndExport, ImportCompareExport, GetApplicationAndServiceLogs, GetApplicationAndServiceLog



