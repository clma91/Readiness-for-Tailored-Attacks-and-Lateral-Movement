Function WriteXMLElement([System.XMl.XmlTextWriter] $XmlWriter, [String] $startElement, [String] $value) {
    $xmlWriter.WriteStartElement($startElement)
    $xmlWriter.WriteValue($value)
    $xmlWriter.WriteEndElement()
}

Function IsCAPI2Enabled([System.XMl.XmlTextWriter] $XmlWriter, [int] $requiredLogSize) {
    [xml]$capi2 = wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml
    $capi2Enabled = $capi2.channel.enabled
    $currentLogSize = $capi2.channel.logging.maxsize -as [int]
    if ($capi2Enabled -eq "true" -and $currentLogSize -ge $requiredLogSize) {
        WriteXMLElement $xmlWriter "CAPI2" "EnabledGoodLogSize"
        WriteXMLElement $xmlWriter "CAPI2LogSize" "$currentLogSize"
    } elseif ($capi2Enabled -eq "true" -and $currentLogSize -lt $requiredLogSize) {
        WriteXMLElement $xmlWriter "CAPI2" "EnabledBadLogSize"
        WriteXMLElement $xmlWriter "CAPI2LogSize" "$currentLogSize"
    } else {
        WriteXMLElement $xmlWriter "CAPI2" "Disabled"
    }
}

Function IsForceAuditPoliySubcategoryEnabeled([System.XMl.XmlTextWriter] $XmlWriter) {
    $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $name = "SCENoApplyLegacyAuditPolicy"
    try {
        $auditPoliySubcategoryKey = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        if ($auditPoliySubcategoryKey.SCENoApplyLegacyAuditPolicy -eq 1) {
            WriteXMLElement $xmlWriter "ForceAuditPolicySubcategory" "Enabled"
        } else {
            WriteXMLElement $xmlWriter "ForceAuditPolicySubcategory" "Disabled"
        }
    }
    catch {
        WriteXMLElement $xmlWriter "ForceAuditPolicySubcategory" "NotDefined"
    }
}

Function IsSysmonInstalled([System.XMl.XmlTextWriter] $XmlWriter) {
    $service = $null

    try {
        $service = Get-Service -Name Sysmon*
    } catch {
        WriteXMLElement $xmlWriter "Sysmon" "NotInstalled"
    }
    
    if ($service.Status -ne "Running") {
        WriteXMLElement $xmlWriter "Sysmon" "InstalledNotRunning"
    } else {
        WriteXMLElement $xmlWriter "Sysmon" "Installed"
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

Export-ModuleMember -Function WriteXML,IsCAPI2Enabled, IsForceAuditPoliySubcategoryEnabeled, IsSysmonInstalled, GetAndAnalyseAuditPolicies