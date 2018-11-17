Function GetAuditPolicies($importPath) {
    Write-Host "Get RSoP"
    $isCurrentPath = $true
    $pathRSOPXML = $PSScriptRoot + "\rsop.xml"

    if ($importPath) {
        $isCurrentPath = $false
        $pathRSOPXML = $importPath + "\rsop.xml"
    } else {
        Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null
    }

    $rsopResult = Get-Content $pathRSOPXML
    
    if ($isCurrentPath) {
        Remove-Item $pathRSOPXML
    }
        
    return $rsopResult
}

Function AnalyseAuditPolicies ([xml] $rsopResult){    
    Write-Host "Check RSoP"
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
            Write-Host " - $auditSettingSubcategoryName is not configured" -ForegroundColor Red
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
            Write-Host " - `'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`' enabled" -ForegroundColor Green
            return $result
        } else {
            $result.Add("ForceAuditPolicySubcategory", "Disabled")
            Write-Host " - `'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`' disabled" -ForegroundColor Red
            return $result
        }
    } else {
        $result.Add("ForceAuditPolicySubcategory", "NotDefined")
        Write-Host " - `'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`' not defined" -ForegroundColor Red
        return $result
    }
}

Function GetService($name) {
    try {
        return Get-Service -Name $name
    } catch {
        throw
    }
}

Function IsSysmonInstalled($service) {
    Write-Host "Check Sysmon"
    $result = @{}

    try {
        if ($service.Status -ne "Running") {
            $result.Add("Sysmon", "InstalledNotRunning")
            Write-Host " - Sysmon is installed but not running as a service" -ForegroundColor Yellow
            return $result
        } else {
            $result.Add("Sysmon", "InstalledAndRunning")
            Write-Host " - Sysmon is installed and running as a service" -ForegroundColor Green
            return $result
        }
    } catch {
        $result.Add("Sysmon", "NotInstalled")
        Write-Host " - Sysmon is not installed" -ForegroundColor Red
        return $result
    }
}

Function GetCAPI2 {
    return wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml
}

Function IsCAPI2Enabled([xml] $capi2, [int] $requiredLogSize) {
    Write-Host "Check CAPI2"
    $capi2Enabled = $capi2.channel.enabled
    $currentLogSize = $capi2.channel.logging.maxsize -as [int]
    $result = @{}
    if ($requiredLogSize -lt 4194304) {
        Write-Host " - Defined Log Size smaller than 4MB ($requiredLogSize) => set default value 4MB (4194304)" -ForegroundColor Yellow
        $requiredLogSize = 4194304
    }

    if ($capi2Enabled -eq "true" -and $currentLogSize -ge $requiredLogSize) {
        $result.Add("CAPI2", "EnabledGoodLogSize")
        $result.Add("CAPI2LogSize", "$currentLogSize")
        Write-Host " - CAPI2 enabled with a good log size of $currentLogSize (>= $requiredLogSize)" -ForegroundColor Green
        return $result
    } elseif ($capi2Enabled -eq "true" -and $currentLogSize -lt $requiredLogSize) {
        $result.Add("CAPI2", "EnabledBadLogSize")
        $result.Add("CAPI2LogSize", "$currentLogSize")
        Write-Host " - CAPI2 enabled with a bad log size of $currentLogSize (<= $requiredLogSize)" -ForegroundColor Red
        return $result
    } else {
        $result.Add("CAPI2", "Disabled")
        Write-Host " - CAPI2 disabled" -ForegroundColor Red
        return $result
    }
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
    $resultXML = $PSScriptRoot + "\resultOfAuditPolicies.xml"
    if ($exportPath) {
        $resultXML = $exportPath + "\resultOfAuditPolicies.xml"
    }
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
    Write-Host "DONE!!!"
}

Export-ModuleMember -Function GetAuditPolicies, AnalyseAuditPolicies, GetRegistryValue, IsForceAuditPoliySubcategoryEnabeled, GetService, IsSysmonInstalled, GetCAPI2, IsCAPI2Enabled, MergeHashtables, WriteXML