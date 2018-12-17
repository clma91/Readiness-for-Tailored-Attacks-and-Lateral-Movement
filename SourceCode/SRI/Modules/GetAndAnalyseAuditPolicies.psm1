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
    Write-Host "Checking `'Audit: Force audit policy subcategory settings to override audit policy category settings`'"
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
    $Service = Get-WmiObject win32_service -Filter "Description = 'System Monitor service'"
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

Function IsForceAuditPolicyDomainEnabeled ([String] $PolicyName) {
    Write-Host "Checking `'Audit: Force audit policy subcategory settings to override audit policy category settings`'"

    $Domain = Get-WmiObject Win32_ComputerSystem -ComputerName "localhost" | Select-Object -ExpandProperty Domain
    $PolicyId = Get-GPO -Name $PolicyName | Select-Object -ExpandProperty id
    
    $SecEditPath =  "\\$Domain\SYSVOL\$Domain\Policies\{$PolicyId}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    $ForceAuditPolicyEnabled = "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1"
    $ForceAuditPolicyDisabled = "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,0"
    $AuditSettings = @{}

    if (Test-Path $SecEditPath) {
        $RegistryKeyValue = Get-Content $SecEditPath
        if ($RegistryKeyValue -contains $ForceAuditPolicyEnabled) {
            $AuditSettings.Add("ForceAuditPolicySubcategory", "Enabled")
        } elseif ($RegistryKeyValue -contains $ForceAuditPolicyDisabled) {
            $AuditSettings.Add("ForceAuditPolicySubcategory", "Disabled")
        } else {
            $AuditSettings.Add("ForceAuditPolicySubcategory", "NotDefined")
        }
    } 
    return $AuditSettings
}

Function CheckDomainAndPolicy([String] $PolicyName) {
    $Domain = Get-WmiObject Win32_ComputerSystem -ComputerName "localhost" | Select-Object -ExpandProperty Domain
    try {
        $GPO = Get-GPO -Name "$PolicyName" -ErrorAction Stop
    }
    catch {
        Write-Host "The group policy with the name `'$PolicyName`' does not exist" -ForegroundColor Red
        return
    }
    
    $PolicyId = Get-GPO -Name $PolicyName | Select-Object -ExpandProperty id
    $PolicyCSVPath = "\\$Domain\SYSVOL\$Domain\Policies\{$PolicyId}\MACHINE\Microsoft\Windows NT\Audit"

    if (Test-Path $PolicyCSVPath) {
        return $PolicyCSVPath + "\audit.csv"
    }
    else {
        Write-Host "For the group policy `'$PolicyName`' exists no `'Advanced Audit Policy Configuration`' definition" -ForegroundColor Red
        return
    }
}

Function GetDomainAuditPolicy ([String] $PolicyName) {
    $PolicyCSV = CheckDomainAndPolicy $PolicyName

    if ([System.IO.File]::Exists($PolicyCSV)) {
        Write-Host "Get audit settings from group policy: `'$PolicyName`'"
        $AuditSettings = @{}
        $Policy = Import-Csv $PolicyCSV -Encoding UTF8

        foreach ($Element in $Policy) {
            $AuditSettings.Add(($Element.Subcategory -replace (" ")), $Element."Setting Value")
        }  
        return $AuditSettings
    } else {
        Write-Host "For this Group Policy exist no auditing definition" -ForegroundColor Red
        return
    }
}

Function GetAllDomainAuditPolicies {
    try {
        $GPOs = Get-GPO -all | Select-Object DisplayName, Id
    }
    catch {
        Write-Host "Your system is not associated with an Active Directory domain or forest" -ForegroundColor Red
        return
    }
    
    $AuditSettingsPerPolicy = @{}
    $AuditSettings =@{}

    foreach ($GPO in $GPOs) {
        $AuditSettings = GetDomainAuditPolicy $GPO.DisplayName
        $AuditSettingsPerPolicy.Add($GPO.DisplayName, $AuditSettings)
    }
    
    return $AuditSettingsPerPolicy
}

Function GetAuditSettingValues ([Hashtable] $AuditSettings, [Array] $TargetAuditSettings) {
    $Result = @{}
    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$AuditSettingValue = 0
    <# Check if all required Advanced Audit Policies accoriding to JPCERT/CCs study 
    "Detecting Lateral Movement through Tracking Event Logs" are configured in the right manner #>
    foreach ($AuditSetting in $AuditSettings.GetEnumerator()) {
        if ($TargetAuditSettings -notcontains $AuditSetting.Name) {
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
    Write-Host $Result.Count
    return $Result
}

Function CompareToTargetList ([Hashtable] $AuditSettings, [Array] $TargetAuditSettings) {
    <# Check if all required Advanced Audit Policies accoriding to JPCERT/CCs study 
    "Detecting Lateral Movement through Tracking Event Logs" are configured #>
    $Result = @{}
    foreach ($TargetAuditSetting in $TargetAuditSettings) {
        if ($AuditSettings.keys -notcontains $TargetAuditSetting) {
            $Result.Add(($TargetAuditSetting -replace (" ")), "NotConfigured")
        }
    }
    return $Result
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

Function AnalyseAuditPolicies ($AuditSettings) {
    Write-Host "Analysing Audit Policies"
    $TargetAuditSettings = GetAuditPoliciesTargetList
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
    
    $AuditSettingsCompared = CompareToTargetList $AuditSettings $TargetAuditSettings
    $AuditSettingsValues = GetAuditSettingValues $AuditSettings $TargetAuditSettings
    $Result = MergeHashtables $AuditSettingsCompared $AuditSettingsValues

    return $Result
}

Function MergeHashtables {
    $Output = @{}
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

        $OrderedResultCollection = $ResultCollection.GetEnumerator() | Sort-Object -Property name 
            
        foreach ($Item in $OrderedResultCollection) {
            WriteXMLElement $XMLWriter $Item.name $Item.Value
        }
    
        $XMLWriter.WriteEndElement()
        $XMLWriter.WriteEndDocument()
        $XMLWriter.Flush()
        $XMLWriter.Close()
        Write-Host "Done Audit Policies"
    }
}

Export-ModuleMember -Function GetCAPI2, IsCAPI2Enabled, GetRegistryValue, IsForceAuditPolicyEnabeled, IsSysmonInstalled, IsForceAuditPolicyDomainEnabeled, GetAuditPolicies, GetDomainAuditPolicy, GetAllDomainAuditPolicies, AnalyseAuditPolicies, MergeHashtables, WriteXML, GetAuditPoliciesTargetList, GetAuditSettingValues, CompareToTargetList