Function IsCAPI2Enabled([int] $requiredLogSize) {
    [xml]$capi2 = wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml
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

Function IsForceAuditPoliySubcategoryEnabeled {
    $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $name = "SCENoApplyLegacyAuditPolicy"
    $result = @{}

    try {
        $auditPoliySubcategoryKey = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        if ($auditPoliySubcategoryKey.SCENoApplyLegacyAuditPolicy -eq 1) {
            $result.Add("ForceAuditPolicySubcategory", "Enabled")
            return $result
        } else {
            $result.Add("ForceAuditPolicySubcategory", "Disabled")
            return $result
        }
    }
    catch {
        $result.Add("ForceAuditPolicySubcategory", "NotDefined")
        return $result
    }
}

Function IsSysmonInstalled {
    $service = $null
    $result = @{}

    try {
        $service = Get-Service -Name Sysmon*
    } catch {
        $result.Add("Sysmon", "NotInstalled")
        return $result
    }
    
    if ($service.Status -ne "Running") {
        $result.Add("Sysmon", "InstalledNotRunning")
        return $result
    } else {
        $result.Add("Sysmon", "Installed")
        return $result
    }
}

Function GetAndAnalyseAuditPolicies ([String] $currentPath){
    $pathRSOPXML = $currentPath + "\LocalUserAndComputerReport.xml"
    $auditSettingSubcategoryNames = @("Audit Sensitive Privilege Use","Audit Kerberos Service Ticket Operations","Audit Registry","Audit Security Group Management","Audit File System","Audit Process Termination","Audit Logoff","Audit Process Creation","Audit Filtering Platform Connection","Audit File Share","Audit Kernel Object","Audit MPSSVC Rule-Level Policy Change","Audit Non Sensitive Privilege Use","Audit Logon","Audit SAM","Audit Handle Manipulation","Audit Special Logon","Audit Detailed File Share","Audit Kerberos Authentication Service","Audit User Account Management")
    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$auditSettingValue = 0;
    $result = @{}

    Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null;
    [xml]$rsopResult = Get-Content $pathRSOPXML;  
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
    Remove-Item $pathRSOPXML

    return $result
}

Function Merge-Hashtables {
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

Function WriteXML($currentPath, $resultCollection) {
    $resultXML = $currentPath + "\resultOfAuditPolicies.xml"
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
}

Export-ModuleMember -Function WriteXML, IsCAPI2Enabled, IsForceAuditPoliySubcategoryEnabeled, IsSysmonInstalled, GetAndAnalyseAuditPolicies, Merge-Hashtables