#Requires -RunAsAdministrator

Function CheckLegacyAuditPolicy {
    $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $name = "SCENoApplyLegacyAuditPolicy"
    try {
        $legacyAuditPolicyKey = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        if ($legacyAuditPolicyKey.SCENoApplyLegacyAuditPolicy -eq 1) {
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


Function ReadResultantSetOfPolicies {
    $currentPath = (Resolve-Path .\).Path

    $resultXML = (Resolve-Path .\).Path + "\resultOfAuditPolicies.xml"
    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null)
    $xmlWriter.Formatting = "Indented"
    $xmlWriter.Indentation = 1
    $XmlWriter.IndentChar = "`t"
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteStartElement("AuditPolicies")
    
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
            $xmlWriter.WriteStartElement(($auditSettingSubcategoryName -replace (" ")))
            $xmlWriter.WriteValue("NotConfigured")
            $xmlWriter.WriteEndElement()
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
            $xmlWriter.WriteStartElement(($auditSubcategoryName -replace (" ")))
            switch ($auditSettingValue) {
                NoAuditing {  
                    $xmlWriter.WriteValue("NoAuditing")
                }
                Success {
                    $xmlWriter.WriteValue("Success")
                } 
                Failure {
                    $xmlWriter.WriteValue("Failure")
                }
                SuccessAndFailure {
                    $xmlWriter.WriteValue("SuccessAndFailure")
                }
                Default {}
            }
            $xmlWriter.WriteEndElement()
        }    
    }

    # Check if setting forcing basic security auditing (Security Settings\Local Policies\Audit Policy) is ignored to prevent conflicts between similar settings
    $checkLegacyAuditPolicy = CheckLegacyAuditPolicy
    $xmlWriter.WriteStartElement("ForceAuditPolicySubcategory")
    $xmlWriter.WriteValue($checkLegacyAuditPolicy)
    $xmlWriter.WriteEndElement()

    $isSysmonInstalled = IsSysmonInstalled
    $xmlWriter.WriteStartElement("Sysmon")
    $xmlWriter.WriteValue($isSysmonInstalled)
    $xmlWriter.WriteEndElement()

    $xmlWriter.WriteEndElement()
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()

    Remove-Item $pathRSOPXML
}

readResultantSetOfPolicies