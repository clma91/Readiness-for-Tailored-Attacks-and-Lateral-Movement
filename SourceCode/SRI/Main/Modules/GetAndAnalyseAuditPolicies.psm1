Function GetCAPI2 {
    return wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml
}

Function IsCAPI2Enabled([xml] $capi2, [uint32] $requiredLogSize) {
    Write-Host "Checking CAPI2"
    $capi2Enabled = $capi2.channel.enabled
    $currentLogSize = $capi2.channel.logging.maxsize -as [uint32]
    $result = @{}
    if ($requiredLogSize -lt 4194304) {
        $requiredLogSize = 4194304
    }

    if ($capi2Enabled -eq "true" -and $currentLogSize -ge $requiredLogSize) {
        $result.Add("CAPI2", "EnabledGoodLogSize")
        $result.Add("CAPI2LogSize", "$currentLogSize")
    }
    elseif ($capi2Enabled -eq "true" -and $currentLogSize -lt $requiredLogSize) {
        $result.Add("CAPI2", "EnabledBadLogSize")
        $result.Add("CAPI2LogSize", "$currentLogSize")
    }
    else {
        $result.Add("CAPI2", "Disabled")
    }
    return $result
}

Function GetRegistryValue([String] $path, [String] $name) {
    try {
        return Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
    }
    catch {
        return $null
    }
}

Function IsForceAuditPolicyEnabeled([Object] $auditPolicySubcategoryKey) {
    Write-Host "Checking `'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`'"
    $result = @{}

    if ($auditPolicySubcategoryKey) {
        if ($auditPolicySubcategoryKey.SCENoApplyLegacyAuditPolicy -eq 1) {
            $result.Add("ForceAuditPolicySubcategory", "Enabled")
            return $result
        }
        else {
            $result.Add("ForceAuditPolicySubcategory", "Disabled")
            return $result
        }
    }
    else {
        $result.Add("ForceAuditPolicySubcategory", "NotDefined")
        return $result
    }
}

Function IsSysmonInstalled {
    Write-Host "Checking Sysmon"
    $service = Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
    $result = @{}

    if ($service) {
        if ($service.State -ne "Running") {
            $result.Add("Sysmon", "InstalledNotRunning")
            return $result
        }
        else {
            $result.Add("Sysmon", "InstalledAndRunning")
            return $result
        }
    }
    else {
        $result.Add("Sysmon", "NotInstalled")
        return $result
    }
}

Function GetAuditPoliciesTargetList {
    [xml]$targetList = Get-Content ("$PSScriptRoot\..\Config\targetlist_auditpolicies.xml")
    $auditSettings = @()
    foreach ($element in $targetList.AuditPolicies.ChildNodes) {
        if ($element.Localname.StartsWith("Audit")) {
            $auditSettings += ($element.Localname -replace (" "))
        }
    }
    return $auditSettings
}

Function GetAuditPolicies([String] $importPath) {
    $isCurrentPath = $true
    $pathRSOPXML = "$PSScriptRoot\..\rsop.xml"
    Write-Host "Get RSoP"
    
    if ($importPath) {
        $isCurrentPath = $false
        $pathRSOPXML = "$importPath\rsop.xml"
    }

    else {
        try {
            Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null
        }
        catch {
            Write-Host "Necessary Module `'GroupPolicy`' is not provided within this system" -ForegroundColor Red
            Write-Host "Please download: `'Remote Server Administration Tools for Windows 10`'" -ForegroundColor Yellow
            Write-Host "Link https://www.microsoft.com/en-us/download/details.aspx?id=45520" -ForegroundColor Yellow
            return
        }
    }

    if ([System.IO.File]::Exists($pathRSOPXML)) {
        [xml]$rsopResult = Get-Content $pathRSOPXML
    }
    else {
        Write-Host "File $pathRSOPXML does not exist!" -ForegroundColor Red
        return
    } 

    if ($isCurrentPath) {
        Remove-Item $pathRSOPXML
    }
        
    return $rsopResult
}

Function GetDomainAuditPolicy ([String] $policyName) {
    $domain = Get-WmiObject Win32_ComputerSystem -ComputerName "localhost" | Select-Object -ExpandProperty Domain
    
    try {
        $gpo = Get-GPO -Name "$policyName" -ErrorAction Stop
    }
    catch {
        Write-Host "The Group Policy with the name $policyName does not exist" -ForegroundColor Red
        return
    }
    Write-Host "Get Audit Settings from Domain Policy $domain\$policyName"
    $policyId = Get-GPO -Name $policyName | Select-Object -ExpandProperty id
    $policyCSVPath = "\\$domain\SYSVOL\$domain\Policies\{$policyId}\MACHINE\Microsoft\Windows NT\Audit"

    if (Test-Path $policyCSVPath) {
        $policyCSV = $policyCSVPath + "\audit.csv"
    }
    else {
        Write-Host "For this Group Policy exist no definition" -ForegroundColor Red
        return
    }

    if ([System.IO.File]::Exists($policyCSV)) {
        $auditSettings = @{}
        $policy = Import-Csv $policyCSV -Encoding UTF8
        foreach ($element in $policy) {
            $auditSettings.Add($element.Subcategory, $element."Setting Value")
        }
        return $auditSettings
    }
    else {
        Write-Host "For this Group Policy exist no auditing definition" -ForegroundColor Red
        return
    }
}

Function GetAllDomainAuditPolicies {
    Write-Host "Get Audit Settings from all GPOs"
    $domain = Get-WmiObject Win32_ComputerSystem -ComputerName "localhost" | Select-Object -ExpandProperty Domain
    try {
        $gpos = Get-GPO -all | Select-Object DisplayName, Id
    }
    catch {
        Write-Host "Your system is not associated with an Active Directory domain or forest" -ForegroundColor Red
        return
    }
    
    $auditSettingsPerPolicy = @{}

    foreach ($gpo in $gpos) {
        $policyName = $gpo.DisplayName
        $policyId = $gpo.id
        $policyCSVPath = "\\$domain\SYSVOL\$domain\Policies\{$policyId}\MACHINE\Microsoft\Windows NT\Audit"

        if (Test-Path $policyCSVPath) {
            $policyCSV = $policyCSVPath + "\audit.csv"
        }
        else {
            Write-Host "For the Group Policy $policyName exist no defintion" -ForegroundColor Red
            continue
        }
        if ([System.IO.File]::Exists($policyCSV)) {
            $auditSettings = @{}
            $policy = Import-Csv $policyCSV -Encoding UTF8
            foreach ($element in $policy) {
                $auditSettings.Add($element.Subcategory, $element."Setting Value")
            }
            $auditSettingsPerPolicy.Add($gpo.DisplayName, $auditSettings)
        }
        else {
            Write-Host "For the Group Policy $policyName exist no auditing defintion" -ForegroundColor Red
            continue
        }
    }
    return $auditSettingsPerPolicy
}

Function AnalyseAuditPolicies ($auditSettings) {
    Write-Host "Analysing Audit Policies"
    $targetAuditSettings = GetAuditPoliciesTargetList
    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$auditSettingValue = 0
    $result = @{}

    if ($auditSettings.GetType() -eq [System.Xml.XmlDocument]) {
        $auditSettingsRSoP = $auditSettings.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting
        $auditSettings = @{}
        foreach ($auditSettingRSoP in $auditSettingsRSoP) {
            if ($auditSettingRSoP) {
                $auditSettings.Add(($auditSettingRSoP.SubcategoryName -replace (" ")), $auditSettingRSoP.SettingValue)
            }
        }
    } 
    
    <# Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study 
    "Detecting Lateral Movement through Tracking Event Logs" are configured #>
    foreach ($auditSettingSubcategoryName in $targetAuditSettings) {
        if ($auditSettings.keys -notcontains $auditSettingSubcategoryName) {
            $result.Add(($auditSettingSubcategoryName -replace (" ")), "NotConfigured")
        }
    }

    <# Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study 
    "Detecting Lateral Movement through Tracking Event Logs" are configured in the right manner #>
    foreach ($auditSetting in $auditSettings.GetEnumerator()) {
        if ($targetAuditSettings -notcontains $auditsetting.name) {
            continue
        }
        if ($auditSetting.value -and $auditSetting.name) {
            try {
                $auditSettingValue = $auditSetting.value
            }
            catch {
                $auditSettingValue = 0
            }
            $auditSubcategoryName = $auditSetting.name 
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
    $Output = [ordered]@{}
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
    Write-Host "Writing Result XML"
    $resultXML = "$exportPath\result_audit_policies.xml"
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML, $encoding)

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
    Write-Host "Done Audit Policies"
}

Export-ModuleMember -Function GetCAPI2, IsCAPI2Enabled, GetRegistryValue, IsForceAuditPolicyEnabeled, IsSysmonInstalled, GetAuditPolicies, GetDomainAuditPolicy, GetAllDomainAuditPolicies, AnalyseAuditPolicies, MergeHashtables, WriteXML