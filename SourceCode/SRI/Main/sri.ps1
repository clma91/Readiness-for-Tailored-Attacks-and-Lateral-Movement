<#
.SYNOPSIS
    System Readiness Inspector (SRI) checks the readiness for tailored attacks and lateral movement detection
.DESCRIPTION
    SRI is a small but helpful tool to determine the readiness of a system for tailored attacks and lateral movement detection. SRI gives you a visualized overview of you audit policies and you eventlogs.
.PARAMETER Online
    Checks the readiness of the current local system
.PARAMETER OnlineExportPath
    Defines where the results should be stored in the online mode
.PARAMETER Offline
    Checks only the readiness for a system with a provided Resultant Set of Policies and Event Log exports
    Parameter [ImportPath] <String> must be defined
    [ImportPath] <String> must provide rsop.xml, windowslogs.csv, appandservlogs.csv, ...
.PARAMETER AuditPolicies
    Checks only the readiness for a system with a provided Resultant Set of Policies export
    Parameter [ImportPath] <String> must be defined
    [ImportPath] <String> must provide rsop.xml
.PARAMETER EventLogs
    Checks only the readiness for a system with a provided Event Log exports
    Parameter [ImportPath] <String> must be defined
    [ImportPath] <String> must provide windowslogs.csv, appandservlogs.csv, ...
.PARAMETER ImportPath
    Offline-Mode: The following files rsop.xml, windowslogs.csv, appandservlogs.csv, ... must remain at the ImportPath
.PARAMETER ExportPath
    Defines where the results should be stored
.PARAMETER CAPI2LogSize
    Defines the LogSize of CAPI2 (default is 4194304 = 4MB - minimal recommondation from microsoft). Zero will be matched as default.
    4MB = 4194304Bytes = 4 * 1024 * 1024Bytes
    Reference: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749296(v=ws.10)#capi2-diagnostics-in-windows-vista
.PARAMETER GroupPolicy
    Checks the readiness of a specific GroupPolicy
    Parameter [DomainName] <String> must be defined
    Parameter [GroupPolicyName] <String> must be defined
.PARAMETER DomainName
    Defines the domain in which the GroupPolicy to be checked is located
.PARAMETER GroupPolicyName
    Defines the GroupPolicy by the Name of the GroupPolicy to be checked
.PARAMETER AllGroupPolicies
    Checks the readiness of all Group Policies it can find

.EXAMPLE
    ./sri.ps1 -Online

    - Run the System Readiness Inspector locally
    - Results will be written to the current path of execution
    - The CAPI2 log size will set to default (4MB)
.EXAMPLE
    ./sri.ps1 -Online C:/ExportSRI/
    or

    PS C:\>./sri.ps1 -Online -OnlineExportPath C:/ExportSRI/

    - Run the System Readiness Inspector locally
    - Results will be written to the given path (in this example: C:/ExportSRI/)
    - The CAPI2 log size will set to default (4MB)
.EXAMPLE
    ./sri.ps1 -Online C:/ExportSRI/ 5242880
    or
    
    PS C:\>./sri.ps1 -Online -OnlineExportPath C:/ExportSRI/ -CAPI2LogSize 5242880

    - Run the System Readiness Inspector locally
    - Results will be written to the given path (in this example: C:/ExportSRI/)
    - The CAPI2 log size will bet overwritten to the given value (in this example: 5242880 = 5MB)
.EXAMPLE
    .\sri.ps1 -Offline -ImportPath C:/temp/test -ExportPath D:/test

    - Runs the System Readiness Inspector locally
    - The Sytem Readiness Insprector does no collect data from you system, the needed data must be saved at the importpath
    - The System Readiness Inspector needs one XML-File and two CSV-files, named like this: rsop.xml, windowslogs.csv, appandservlogs.csv
    - Results will be written to the given path (in this example D:/test)

.EXAMPLE
    .\sri.ps1 -Offline -EventLogs -ImportPath C:/temp/test -ExportPath D:/test

    - Runs the System Readiness Inspector locally
    - The Sytem Readiness Insprector does no collect data from you system, the needed data must be saved at the importpath
    - The System Readiness Inspector needs two CSV-files named like this: windowslogs.csv, appandservlogs.csv
       - windowslogs.csv, Either with the PowerShell command Get-EventLogs or export from EventViewer
       - appandservlogs.csv, Either with wevutil  
    - Results will be written to the given path (in this example D:/test)
.EXAMPLE
    .\sri.ps1 -Offline -AuditPolicies -ImportPath C:/temp/test -ExportPath D:/test

    - Runs the System Readiness Inspector locally
    - The Sytem Readiness Insprector does no collect data from you system, the needed data must be saved at the importpath
    - The System Readiness Inspector needs one XML-File named like this: rsop.xml
    - Results will be written to the given path (in this example D:/test)
.EXAMPLE
    ./sri.ps1 -GroupPolicy -DomainName 'testdomain.ch' -GroupPolicyName 'Default Group Policy'
    
    - Run the System Readiness Inspector over the given GroupPolicy
    - EventLogs are neither collected nor checked
    - Results will be written to the current path of execution

.EXAMPLE
    ./sri.ps1 -AllGroupPolicies
    
    - Run the System Readiness Inspector over all found Group Policies
    - EventLogs are neither collected nor checked
    - Results will be written to the current path of execution

.NOTES
    Authors: Lukas Kellenberger, Claudio Mattes
    Date:   December 21, 2018
#>

[CmdletBinding(DefaultParametersetName = 'None')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Online", Position = 0)]
    [switch]
    $Online,

    [Parameter(Mandatory = $false, ParameterSetName = "Online")]
    [String]
    $OnlineExportPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline", Position = 0)]
    [switch]
    $Offline,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position = 1)]
    [switch]
    $AuditPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position = 1)]
    [switch]
    $EventLogs,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline", Position = 2)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ImportPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position = 3)]
    [String]
    $ExportPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline")]
    [Parameter(Mandatory = $false, ParameterSetName = "Online")]
    [int]
    $CAPI2LogSize,

    [Parameter(Mandatory = $true, ParameterSetName = "GroupPolicy", Position = 0)]
    [switch]
    $GroupPolicy,

    [Parameter(Mandatory = $true, ParameterSetName = "GroupPolicy", Position = 1)]
    [String]
    $GroupPolicyName,

    [Parameter(Mandatory = $true, ParameterSetName = "AllGroupPolicies", Position = 0)]
    [switch]
    $AllGroupPolicies    
)
#Requires -RunAsAdministrator
Import-Module ("$PSScriptRoot\Modules\GetAndAnalyseAuditPolicies.psm1") -Force
Import-Module ("$PSScriptRoot\Modules\GetAndCompareLogs.psm1") -Force
Import-Module ("$PSScriptRoot\Modules\Visualize.psm1") -Force

Function GroupPolicy ($OnlineExportPath) {
    $auditSettingsDomain = GetDomainAuditPolicies $GroupPolicyName
    if ($auditSettingsDomain) {
        $auditSettings = AnalyseAuditPolicies $auditSettingsDomain
        WriteXML $auditSettings $OnlineExportPath
        VisualizeAuditPolicies $OnlineExportPath
    }
}

Function AllGroupPolicies ($OnlineExportPath) {
    $auditSettingsPerPolicy = GetAllDomainAuditPolicies
    if ($auditSettingsPerPolicy) {
        foreach ($auditSettingPerPolicy in $auditSettingsPerPolicy.GetEnumerator()) {
            Write-Host "Processing Group Policy: " $auditSettingPerPolicy.name
            $policyName = ($policyName -replace (" "))
            $resultPDF = $OnlineExportPath + "\results.pdf"
            $new_resultPDF = $OnlineExportPath + "\results_" + $policyName + ".pdf"
            $resultAuditPolicies = $OnlineExportPath + "\result_audit_policies.xml"
            $new_resoltOfAuditPolicies = $OnlineExportPath + "\result_audit_policies" + $policyName + ".xml"
    
            $auditSetting = AnalyseAuditPolicies $auditSettingPerPolicy.value
            WriteXML $auditSetting $OnlineExportPath
            VisualizeAuditPolicies $OnlineExportPath
    
            if ([System.IO.File]::Exists($new_resultPDF)) {
                Remove-Item -Path $new_resultPDF
            }
            elseif ([System.IO.File]::Exists($new_resoltOfAuditPolicies)) {
                Remove-Item -Path $new_resoltOfAuditPolicies
            }
            else {
                Rename-Item -Path $resultAuditPolicies -NewName $new_resoltOfAuditPolicies
                Rename-Item -Path $resultPDF -NewName $new_resultPDF
            }
        } 
    }
}

Function Online ($OnlineExportPath, $CAPI2LogSize) {
    $rsopResult = GetAuditPolicies
    if ($rsopResult) {
        $auditPolicies = AnalyseAuditPolicies $rsopResult

        <# Check if setting forcing basic security auditing (Security Settings\Local Policies\Security Options) 
           is ignored to prevent conflicts between similar settings #>
        $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $name = "SCENoApplyLegacyAuditPolicy"
        $auditPoliySubcategoryKey = GetRegistryValue $path $name
        $auditPolicySubcategory = IsForceAuditPolicyEnabeled $auditPoliySubcategoryKey
    
        $sysmon = IsSysmonInstalled $sysmonService
    
        $capi2 = GetCAPI2
        $capi2Result = IsCAPI2Enabled $capi2 $CAPI2LogSize
    
        $resultCollection = MergeHashtables $auditPolicies $auditPolicySubcategory $sysmon $capi2Result
    
        WriteXML $resultCollection $OnlineExportPath
    
        GetEventLogsAndExport $OnlineExportPath
        GetApplicationAndServiceLogs $OnlineExportPath
        $eventLogsDone = ImportCompareExport $ImportPath $OnlineExportPath
        if ($eventLogsDone) {
            VisualizeAll $OnlineExportPath
        } else {
            VisualizeAuditPolicies $OnlineExportPath
        }
    }
}

Function OfflineAuditPolicies ($ImportPath, $ExportPath) {
    $rsopResult = GetAuditPolicies $ImportPath
    if ($rsopResult) {
        $auditPolicies = AnalyseAuditPolicies $rsopResult
        WriteXML $auditPolicies $ExportPath
        VisualizeAuditPolicies $ExportPath
    }
}

Function OfflineEventLogs ($ImportPath, $ExportPath) {
    $eventLogsDone = ImportCompareExport $ImportPath $ExportPath
    if ($eventLogsDone) {
        VisualizeEventLogs $ExportPath
    }
}

Function Offline ($ImportPath, $ExportPath) {
    $rsopResult = GetAuditPolicies $ImportPath
    if ($rsopResult) {
        $auditPolicies = AnalyseAuditPolicies $rsopResult
        WriteXML $auditPolicies $ExportPath
        $eventLogsDone = ImportCompareExport $ImportPath $ExportPath
        if ($eventLogsDone) {
            VisualizeAll $ExportPath
        } else {
            VisualizeAuditPolicies $ExportPath
        }
    }
}

Function CheckExportPath($exportPath) {
    if ($exportPath) {
        if (Test-Path -Path $exportPath) {
            return $exportPath
        }
        else {
            return $null
        } 
    }
    else {
        return $PSScriptRoot
    }
}

Function CheckGroupPolicyModule {
    if (Get-Module -Name "GroupPolicy") {
        return $true
    }
    else {
        return $false
    }
}

switch ($PsCmdLet.ParameterSetName) {
    'None' {
        Write-Host "Please define the Script-Mode [-GroupPolicy|-Online|-Offline]" -ForegroundColor Red
        continue
    }
    'AllGroupPolicies' {
        Write-Host "Get all Group Policies"
        $OnlineExportPath = CheckExportPath $OnlineExportPath
        AllGroupPolicies $OnlineExportPath
    }
    'GroupPolicy' {
        Write-Host "Get Group Policy"
        $OnlineExportPath = CheckExportPath $OnlineExportPath
        $ImportPath = $OnlineExportPath

        if ($OnlineExportPath) {
            GroupPolicy $OnlineExportPath
        }
        else {
            Write-Host "Defined ExportPath $OnlineExportPath does not exist or your user has no access rights" -ForegroundColor Red
        }
        continue
    }
    'Online' {
        Write-Host "Online-Mode"
        $OnlineExportPath = CheckExportPath $OnlineExportPath
        $ImportPath = $OnlineExportPath

        if ($OnlineExportPath) {
            Online $OnlineExportPath $CAPI2LogSize
        }
        else {
            Write-Host "Defined ExportPath $OnlineExportPath does not exist or your user has no access rights" -ForegroundColor Red
        }
        continue
    }
    'Offline' {
        $ExportPath = CheckExportPath $ExportPath
        try {
            $ImportPathExist = Test-Path -Path $ImportPath
        }
        catch {
            $ImportPathExist = $false
        }            

        if ($ExportPath) {
            if (-not $ImportPathExist) {
                Write-Host "Defined ImportPath does not exist or your user has no access rights" -ForegroundColor Red
            }
            else {
                if ($AuditPolicies) {
                    Write-Host "Offline-Mode AuditPolicies"
                    OfflineAuditPolicies $ImportPath $ExportPath
                }
                elseif ($EventLogs) {
                    Write-Host "Offline-Mode EventLogs"
                    OfflineEventLogs $ImportPath $ExportPath
                }
                else {
                    Write-Host "Offline-Mode"
                    Offline $ImportPath $ExportPath
                }
            }
        }
        else {
            Write-Host "Defined ExportPath $ExportPath does not exist or your user has no access rights" -ForegroundColor Red
        }
        continue
    }
    default {
        return
    }
}