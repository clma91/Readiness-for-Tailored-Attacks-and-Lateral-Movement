Function GetCAPI2 {
    return wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml
}

Function IsCAPI2Enabled([xml] $capi2, [int] $requiredLogSize) {
    $capi2Enabled = $capi2.channel.enabled
    $currentLogSize = $capi2.channel.logging.maxsize -as [int]
    $result = @{}

    if ($capi2Enabled -eq "true" -and $currentLogSize -ge $requiredLogSize) {
        $result.Add("CAPI2", "EnabledGoodLogSize")
        $result.Add("CAPI2LogSize", "$currentLogSize")
        return $result
    } elseif ($capi2Enabled -eq "true" -and $currentLogSize -lt $requiredLogSize) {
        $result.Add("CAPI2", "EnabledBadLogSize")
        $result.Add("CAPI2LogSize", "$currentLogSize")
        return $result
    } else {
        $result.Add("CAPI2", "Disabled")
        return $result
    }
}

Function GetRegistryValue($path, $name) 
{
    try {
        return Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
    } catch {
        return $null
    }
}

Function IsForceAuditPoliySubcategoryEnabeled($auditPoliySubcategoryKey) {
    Write-Host "Check `'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`'"
    $result = @{}

    if ($auditPoliySubcategoryKey) {
        if ($auditPoliySubcategoryKey.SCENoApplyLegacyAuditPolicy -eq 1) {
            $result.Add("ForceAuditPolicySubcategory", "Enabled")
            return $result
        } else {
            $result.Add("ForceAuditPolicySubcategory", "Disabled")
            return $result
        }
    } else {
        $result.Add("ForceAuditPolicySubcategory", "NotDefined")
        return $result
    }
}

Function GetService($name) {
    Try {
        return Get-Service -Name $name -ErrorAction Stop
    } Catch [Microsoft.PowerShell.Commands.ServiceCommandException]{
        return $null
    }
}

Function IsSysmonInstalled($service) {
    Write-Host "Check Sysmon"
    $result = @{}

    if($service) {
        if ($service.Status -ne "Running") {
            $result.Add("Sysmon", "InstalledNotRunning")
            return $result
        } else {
            $result.Add("Sysmon", "InstalledAndRunning")
            return $result
        }
    } else {
        $result.Add("Sysmon", "NotInstalled")
        return $result
    }
}

Function GetAuditPolicies($importPath) {
    Write-Host "Get RSoP"
    $isCurrentPath = $true
    $pathRSOPXML = $PSScriptRoot + "\rsop.xml"

    if ($importPath) {
        $isCurrentPath = $false
        $pathRSOPXML = $importPath + "\rsop.xml"
    } else {
        Write-Host "Get-Rsop"
        Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null
    }

    if ([System.IO.File]::Exists($pathRSOPXML)) {
        $rsopResult = Get-Content $pathRSOPXML
    } else {
        Write-Host "File $pathRSOPXML does not exist!" -ForegroundColor Red
        return
    } 

    if ($isCurrentPath) {
        Remove-Item $pathRSOPXML
    }
        
    return $rsopResult
}

Function AnalyseAuditPolicies ([xml] $rsopResult){    
    $auditSettingSubcategoryNames = @("Audit Sensitive Privilege Use","Audit Kerberos Service Ticket Operations","Audit Registry","Audit Security Group Management","Audit File System","Audit Process Termination","Audit Logoff","Audit Process Creation","Audit Filtering Platform Connection","Audit File Share","Audit Kernel Object","Audit MPSSVC Rule-Level Policy Change","Audit Non Sensitive Privilege Use","Audit Logon","Audit SAM","Audit Handle Manipulation","Audit Special Logon","Audit Detailed File Share","Audit Kerberos Authentication Service","Audit User Account Management")
    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$auditSettingValue = 0
    $result = @{}
    
    $auditSettings = $rsopResult.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting

    # Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study "Detecting Lateral Movement through Tracking Event Logs" are configured
    foreach($auditSettingSubcategoryName in $auditSettingSubcategoryNames) {
        if($auditSettings.SubcategoryName -notcontains $auditSettingSubcategoryName){
            $result.Add(($auditSettingSubcategoryName -replace (" ")), "NotConfigured")
        }
    }

    # Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study "Detecting Lateral Movement through Tracking Event Logs" are configured in the right manner
    foreach($auditSetting in $auditSettings) {
        if($auditSetting) {
            try {
                $auditSettingValue = $auditSetting.SettingValue
            }
            catch {
                $auditSettingValue = 0
            }
            $auditSubcategoryName = $auditSetting.SubcategoryName 
            switch ($auditSettingValue) {
                NoAuditing {  
                    $auditSettingValueString = "NoAuditing"
                    continue
                }
                Success {
                    $auditSettingValueString = "Success"
                    continue
                } 
                Failure {
                    $auditSettingValueString = "Failure"
                    continue
                }
                SuccessAndFailure {
                    $auditSettingValueString = "SuccessAndFailure"
                    continue
                }
                Default { continue }
            }
            $result.Add(($auditSubcategoryName -replace (" ")), $auditSettingValueString)
        }    
    }
    return $result
}

Function MergeHashtables {
    $Output =  [ordered]@{}
    ForEach ($Hashtable in ($Input + $Args)) {
        If ($Hashtable -is [Hashtable]) {
            ForEach ($Key in $Hashtable.Keys) {
                $Output.$Key = $Hashtable.$Key
            }
        }
    }
    return $Output
}

Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $startElement, [String] $value) {
    $xmlWriter.WriteStartElement($startElement)
    $xmlWriter.WriteValue($value)
    $xmlWriter.WriteEndElement()
}

Function WriteXML($resultCollection, $exportPath) {
    Write-Host "Write Result XML"
    $resultXML = $exportPath + "\resultOfAuditPolicies.xml"
    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML, $Null)

    $xmlWriter.Formatting = "Indented"
    $xmlWriter.Indentation = 1
    $xmlWriter.IndentChar = "`t"
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteStartElement("AuditPolicies")

    foreach ($item in $resultCollection.keys) {
        WriteXMLElement $xmlWriter $item $resultCollection.$item
    }

    $xmlWriter.WriteEndElement()
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()
    Write-Host "DONE Audit Policies!!!"
}

Export-ModuleMember -Function GetCAPI2, IsCAPI2Enabled, GetRegistryValue, IsForceAuditPoliySubcategoryEnabeled, GetService, IsSysmonInstalled, GetAuditPolicies, AnalyseAuditPolicies, MergeHashtables, WriteXML