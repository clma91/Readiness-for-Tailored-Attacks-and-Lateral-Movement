Function IsCAPI2Enabled {
    [xml]$capi2 = wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml
    $capi2Enabled = $capi2.channel.enabled
    $capi2LogSize = $capi2.channel.logging.maxsize -as [int]
    if ($capi2Enabled -eq "true" -and $capi2LogSize -ge 4194304) {
        return "EnabledGoodLogSize"
    } elseif ($capi2Enabled -eq "true" -and $capi2LogSize -lt 4194304) {
        return "EnabledBadLogSize"
    } else {
        return "Disabled"
    }
}

Function IsForceAuditPoliySubcategoryEnabeled {
    $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $name = "SCENoApplyLegacyAuditPolicy"
    try {
        $auditPoliySubcategoryKey = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        if ($auditPoliySubcategoryKey.SCENoApplyLegacyAuditPolicy -eq 1) {
            return "Enabled"
        } else {
            return "Disabled"
        }
    }
    catch {
        return "NotDefined"
    }
}

Function IsSysmonInstalled {
    $service = $null

    try {
        $service = Get-Service -Name Sysmon*
    } catch {
        return "NotInstalled"
    }
    
    if ($service.Status -ne "Running") {
        return "InstalledNotRunning"
    } else {
        return "Installed"
    }
}

Function GetAndAnalyseAuditPolicies ([String] $currentPath, [System.XMl.XmlTextWriter] $XmlWriter){
    $pathRSOPXML = $currentPath + "\LocalUserAndComputerReport.xml"
    Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null;
    [xml]$rsopResult = Get-Content $pathRSOPXML;
    $auditSettingSubcategoryNames = @("Audit Sensitive Privilege Use","Audit Kerberos Service Ticket Operations","Audit Registry","Audit Security Group Management","Audit File System","Audit Process Termination","Audit Logoff","Audit Process Creation","Audit Filtering Platform Connection","Audit File Share","Audit Kernel Object","Audit MPSSVC Rule-Level Policy Change","Audit Non Sensitive Privilege Use","Audit Logon","Audit SAM","Audit Handle Manipulation","Audit Special Logon","Audit Detailed File Share","Audit Kerberos Authentication Service","Audit User Account Management")
    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$auditSettingValue = 0;
    
    $auditSettings = $rsopResult.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting

    # Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study "Detecting Lateral Movement through Tracking Event Logs" are configured
    foreach($auditSettingSubcategoryName in $auditSettingSubcategoryNames) {
        if($auditSettings.SubcategoryName -notcontains $auditSettingSubcategoryName){
            WriteXMLElement $xmlWriter ($auditSettingSubcategoryName -replace (" ")) "NotConfigured"
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
            WriteXMLElement $xmlWriter ($auditSubcategoryName -replace (" ")) $auditSettingValueString
        }    
    }
    Remove-Item $pathRSOPXML
}

Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $startElement, [String] $value) {
    $xmlWriter.WriteStartElement($startElement)
    $xmlWriter.WriteValue($value)
    $xmlWriter.WriteEndElement()
}

Function WriteXML {
    $currentPath = (Resolve-Path .\).Path
    $resultXML = $currentPath + "\resultOfAuditPolicies.xml"
    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null)
    $xmlWriter.Formatting = "Indented"
    $xmlWriter.Indentation = 1
    $XmlWriter.IndentChar = "`t"
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteStartElement("AuditPolicies")

    GetAndAnalyseAuditPolicies $currentPath $xmlWriter 

    # Check if setting forcing basic security auditing (Security Settings\Local Policies\Security Options) is ignored to prevent conflicts between similar settings
    $isForceAuditPoliySubcategoryEnabeled = IsForceAuditPoliySubcategoryEnabeled
    WriteXMLElement $xmlWriter "ForceAuditPolicySubcategory" $isForceAuditPoliySubcategoryEnabeled

    # Check if Sysmon is installed and running as a service
    $isSysmonInstalled = IsSysmonInstalled
    WriteXMLElement $xmlWriter "Sysmon" $isSysmonInstalled

    # Check if CAPI2 is enabled and has a minimum log size of 4MB
    $isCAPI2Enabled = IsCAPI2Enabled
    WriteXMLElement $xmlWriter "CAPI2" $isCAPI2Enabled

    $xmlWriter.WriteEndElement()
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()
}

Export-ModuleMember -Function WriteXML