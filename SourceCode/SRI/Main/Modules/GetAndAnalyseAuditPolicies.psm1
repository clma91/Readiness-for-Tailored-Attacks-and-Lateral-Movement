Function GetCAPI2 {
    return [xml](wevtutil gl Microsoft-Windows-CAPI2/Operational /f:xml)
}

Function IsCAPI2Enabled([xml] $CAPI2, [uint32] $RequiredLogSize) {
    Write-Host "Checking CAPI2"
    $CAPI2Enabled = $CAPI2.channel.enabled
    $CurrentLogSize = $CAPI2.channel.logging.maxsize -as [uint32]
    $Result = @{}
    if ($RequiredLogSize -lt 4194304) {
        $RequiredLogSize = 4194304
    }

    if ($CAPI2Enabled -eq "true" -and $CurrentLogSize -ge $RequiredLogSize) {
        $Result.Add("CAPI2", "EnabledGoodLogSize")
        $Result.Add("CAPI2LogSize", "$CurrentLogSize")
    }
    elseif ($CAPI2Enabled -eq "true" -and $CurrentLogSize -lt $RequiredLogSize) {
        $Result.Add("CAPI2", "EnabledBadLogSize")
        $Result.Add("CAPI2LogSize", "$CurrentLogSize")
    }
    else {
        $Result.Add("CAPI2", "Disabled")
    }
    return $Result
}

Function GetRegistryValue([String] $Path, [String] $Name) {
    try {
        return Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
        return $null
    }
}

Function IsForceAuditPolicyEnabeled([Object] $AuditPolicySubcategoryKey) {
    Write-Host "Checking `'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`'"
    $Result = @{}

    if ($AuditPolicySubcategoryKey) {
        if ($AuditPolicySubcategoryKey.SCENoApplyLegacyAuditPolicy -eq 1) {
            $Result.Add("ForceAuditPolicySubcategory", "Enabled")
            return $Result
        }
        else {
            $Result.Add("ForceAuditPolicySubcategory", "Disabled")
            return $Result
        }
    }
    else {
        $Result.Add("ForceAuditPolicySubcategory", "NotDefined")
        return $Result
    }
}

Function IsSysmonInstalled {
    Write-Host "Checking Sysmon"
    $Service = Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
    $Result = @{}

    if ($Service) {
        if ($Service.State -ne "Running") {
            $Result.Add("Sysmon", "InstalledNotRunning")
            return $Result
        }
        else {
            $Result.Add("Sysmon", "InstalledAndRunning")
            return $Result
        }
    }
    else {
        $Result.Add("Sysmon", "NotInstalled")
        return $Result
    }
}

Function GetAuditPoliciesTargetList {
    [xml]$targetList = Get-Content ("$PSScriptRoot\..\Config\targetlist_auditpolicies.xml")
    $AuditSettings = @()

    foreach ($Element in $targetList.AuditPolicies.ChildNodes) {
        if ($Element.Localname.StartsWith("Audit")) {
            $AuditSettings += ($Element.Localname -replace (" "))
        }
    }
    return $AuditSettings
}

Function GetAuditPolicies([String] $ImportPath) {
    $IsCurrentPath = $true
    $PathRSoPXML = "$PSScriptRoot\..\rsop.xml"
    Write-Host "Get RSoP"

    if ($ImportPath) {
        $IsCurrentPath = $false
        $PathRSoPXML = "$ImportPath\rsop.xml"
    }

    else {
        try {
            Get-GPResultantSetOfPolicy -ReportType Xml -Path  $PathRSoPXML | Out-Null
        }
        catch {
            Write-Host "Necessary Module `'GroupPolicy`' is not provided within this system" -ForegroundColor Red
            Write-Host "Please download: `'Remote Server Administration Tools for Windows 10`'" -ForegroundColor Yellow
            Write-Host "Link https://www.microsoft.com/en-us/download/details.aspx?id=45520" -ForegroundColor Yellow
            return
        }
    }

    if ([System.IO.File]::Exists($PathRSoPXML)) {
        [xml]$RSoPResult = Get-Content $PathRSoPXML
    }
    else {
        Write-Host "File $PathRSoPXML does not exist!" -ForegroundColor Red
        return
    } 

    if ($IsCurrentPath) {
        Remove-Item $PathRSoPXML
    }
        
    return $RSoPResult
}

Function GetDomainAuditPolicy ([String] $PolicyName) {
    $Domain = Get-CimInstance Win32_ComputerSystem -ComputerName "localhost" | Select-Object -ExpandProperty Domain
    
    try {
        $GPO = Get-GPO -Name "$PolicyName" -ErrorAction Stop
    }
    catch {
        Write-Host "The Group Policy with the name $PolicyName does not exist" -ForegroundColor Red
        return
    }
    Write-Host "Get Audit Settings from Domain Policy $Domain\$PolicyName"
    $PolicyId = Get-GPO -Name $PolicyName | Select-Object -ExpandProperty id
    $PolicyCSVPath = "\\$Domain\SYSVOL\$Domain\Policies\{$PolicyId}\MACHINE\Microsoft\Windows NT\Audit"

    if (Test-Path $PolicyCSVPath) {
        $PolicyCSV = $PolicyCSVPath + "\audit.csv"
    }
    else {
        Write-Host "For this Group Policy exist no definition" -ForegroundColor Red
        return
    }

    if ([System.IO.File]::Exists($PolicyCSV)) {
        $AuditSettings = @{}
        $Policy = Import-Csv $PolicyCSV -Encoding UTF8
        foreach ($Element in $Policy) {
            $AuditSettings.Add($Element.Subcategory, $Element."Setting Value")
        }
        return $AuditSettings
    }
    else {
        Write-Host "For this Group Policy exist no auditing definition" -ForegroundColor Red
        return
    }
}

Function GetAllDomainAuditPolicies {
    Write-Host "Get Audit Settings from all GPOs"
    $Domain = Get-CimInstance Win32_ComputerSystem -ComputerName "localhost" | Select-Object -ExpandProperty Domain
    try {
        $GPOs = Get-GPO -all | Select-Object DisplayName, Id
    }
    catch {
        Write-Host "Your system is not associated with an Active Directory domain or forest" -ForegroundColor Red
        return
    }
    
    $AuditSettingsPerPolicy = @{}

    foreach ($GPO in $GPOs) {
        $PolicyName = $GPO.DisplayName
        $PolicyId = $GPO.Id
        $PolicyCSVPath = "\\$Domain\SYSVOL\$Domain\Policies\{$PolicyId}\MACHINE\Microsoft\Windows NT\Audit"

        if (Test-Path $PolicyCSVPath) {
            $PolicyCSV = $PolicyCSVPath + "\audit.csv"
        }
        else {
            Write-Host "For the Group Policy $PolicyName exist no defintion" -ForegroundColor Red
            continue
        }
        if ([System.IO.File]::Exists($PolicyCSV)) {
            $AuditSettings = @{}
            $Policy = Import-Csv $PolicyCSV -Encoding UTF8
            foreach ($Element in $Policy) {
                $AuditSettings.Add($Element.Subcategory, $Element."Setting Value")
            }
            $AuditSettingsPerPolicy.Add($GPO.DisplayName, $AuditSettings)
        }
        else {
            Write-Host "For the Group Policy $PolicyName exist no auditing defintion" -ForegroundColor Red
            continue
        }
    }
    return $AuditSettingsPerPolicy
}

Function AnalyseAuditPolicies ($AuditSettings) {
    Write-Host "Analysing Audit Policies"
    $TargetAuditSettings = GetAuditPoliciesTargetList
    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$AuditSettingValue = 0
    $Result = @{}

    if ($AuditSettings.GetType() -eq [System.Xml.XmlDocument]) {
        $AuditSettingsRSoP = $AuditSettings.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting
        $AuditSettings = @{}
        foreach ($AuditSettingRSoP in $AuditSettingsRSoP) {
            if ($AuditSettingRSoP) {
                $AuditSettings.Add(($AuditSettingRSoP.SubcategoryName -replace (" ")), $AuditSettingRSoP.SettingValue)
            }
        }
    } 
    
    <# Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study 
    "Detecting Lateral Movement through Tracking Event Logs" are configured #>
    foreach ($TargetAuditSetting in $TargetAuditSettings) {
        if ($AuditSettings.keys -notcontains $TargetAuditSetting) {
            $Result.Add(($TargetAuditSetting -replace (" ")), "NotConfigured")
        }
    }

    <# Check if all needed Advanced Audit Policies accoriding to JPCERT/CCs study 
    "Detecting Lateral Movement through Tracking Event Logs" are configured in the right manner #>
    foreach ($AuditSetting in $AuditSettings.GetEnumerator()) {
        if ($TargetAuditSettings -notcontains $auditsetting.Name) {
            continue
        }
        if ($AuditSetting.Value -and $AuditSetting.Name) {
            try {
                $AuditSettingValue = $AuditSetting.Value
            }
            catch {
                $AuditSettingValue = 0
            }
            $AuditSubcategoryName = $AuditSetting.Name 
            switch ($AuditSettingValue) {
                NoAuditing {  
                    $AuditSettingValueString = "NoAuditing"
                    continue
                }
                Success {
                    $AuditSettingValueString = "Success"
                    continue
                } 
                Failure {
                    $AuditSettingValueString = "Failure"
                    continue
                }
                SuccessAndFailure {
                    $AuditSettingValueString = "SuccessAndFailure"
                    continue
                }
                Default { continue }
            }
            $Result.Add(($AuditSubcategoryName -replace (" ")), $AuditSettingValueString)
        }    
    }
    return $Result
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

Function WriteXMLElement([System.XMl.XmlTextWriter] $XMLWriter, [String] $StartElement, [String] $Value) {
    $XMLWriter.WriteStartElement($StartElement)
    $XMLWriter.WriteValue($Value)
    $XMLWriter.WriteEndElement()
}

Function WriteXML([Hashtable] $ResultCollection, [String] $ExportPath) {
    if ($ResultCollection) {
        Write-Host "Writing Result XML"
        $ResultXML = "$ExportPath\result_audit_policies.xml"
        $Encoding = New-Object System.Text.UTF8Encoding($false)
        $XMLWriter = New-Object System.XMl.XmlTextWriter($ResultXML, $Encoding)
    
        $XMLWriter.Formatting = "Indented"
        $XMLWriter.Indentation = 1
        $XMLWriter.IndentChar = "`t"
        $XMLWriter.WriteStartDocument()
        $XMLWriter.WriteStartElement("AuditPolicies")
    
        foreach ($Item in $ResultCollection.keys) {
            WriteXMLElement $XMLWriter $Item $ResultCollection.$Item
        }
    
        $XMLWriter.WriteEndElement()
        $XMLWriter.WriteEndDocument()
        $XMLWriter.Flush()
        $XMLWriter.Close()
        Write-Host "Done Audit Policies"
    }
}

Export-ModuleMember -Function GetCAPI2, IsCAPI2Enabled, GetRegistryValue, IsForceAuditPolicyEnabeled, IsSysmonInstalled, GetAuditPolicies, GetDomainAuditPolicy, GetAllDomainAuditPolicies, AnalyseAuditPolicies, MergeHashtables, WriteXML