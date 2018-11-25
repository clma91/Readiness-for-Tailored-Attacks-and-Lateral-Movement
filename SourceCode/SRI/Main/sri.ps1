<#
.SYNOPSIS
    System Readiness Inspector (SRI) checks the readiness for tailored attacks and lateral movement detection
.DESCRIPTION
    The Description of the SRI...
    ...
    ...
    ...
.PARAMETER Online
    Checks the readiness of the current local system
.PARAMETER OnlineExportPath
    Defines where the results should be stored in the online mode
.PARAMETER Offline
    Checks only the readiness for a system with a provided Resultant Set of Policies and Event Log exports
    Parameter [ImportPath] <String> must be defined
    [ImportPath] <String> must provide rsop.xml, security.csv, system.csv, ...
.PARAMETER AuditPolicies
    Checks only the readiness for a system with a provided Resultant Set of Policies export
    Parameter [ImportPath] <String> must be defined
    [ImportPath] <String> must provide rsop.xml
.PARAMETER EventLogs
    Checks only the readiness for a system with a provided Event Log exports
    Parameter [ImportPath] <String> must be defined
    [ImportPath] <String> must provide security.csv, system.csv, ...
.PARAMETER ImportPath
    Offline-Mode: The following files rsop.xml, security.csv, system.csv, ... must remain at the ImportPath
.PARAMETER ExportPath
    Defines where the results should be stored
.PARAMETER CAPI2LogSize
    Defines the LogSize of CAPI2 (default is 4194304 = 4MB - minimal recommondation from microsoft). Zero will be matched as default.
    4MB = 4194304Bytes = 4 * 1024 * 1024Bytes
    Reference: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749296(v=ws.10)#capi2-diagnostics-in-windows-vista
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
.EXAMPLE
    .\sri.ps1 -Offline -EventLogs -ImportPath C:/temp/test -ExportPath D:/test
.EXAMPLE
    .\sri.ps1 -Offline -AuditPolicies -ImportPath C:/temp/test -ExportPath D:/test
    
.NOTES
    Authors: Lukas Kellenberger, Claudio Mattes
    Date:   December 21, 2018
#>

[CmdletBinding(DefaultParametersetName='None')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Online", Position=0)]
    [switch]
    $Online,

    [Parameter(Mandatory = $false, ParameterSetName = "Online")]
    [String]
    $OnlineExportPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline", Position=0)]
    [switch]
    $Offline,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=1)]
    [switch]
    $AuditPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=1)]
    [switch]
    $EventLogs,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline", Position=2)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ImportPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=3)]
    [String]
    $ExportPath,

    [Parameter(Mandatory = $false)]
    [int]
    $CAPI2LogSize
)
#Requires -RunAsAdministrator
Import-Module ..\GetAndAnalyseAuditPolicies\GetAndAnalyseAuditPolicies.psm1 -Force
Import-Module ..\GetAndCompareLogs\GetAndCompareLogs.psm1 -Force
Import-Module .\visualize.psm1 -Force

Function Online ($OnlineExportPath, $CAPI2LogSize) {
    # Check RSoP
    $rsopResult = GetAuditPolicies 
    # $rsopResult = GetAuditPoliciesDomain
    $auditPolicies = AnalyseAuditPolicies $rsopResult

    <# Check if setting forcing basic security auditing (Security Settings\Local Policies\Security Options) 
       is ignored to prevent conflicts between similar settings #>
    $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $name = "SCENoApplyLegacyAuditPolicy"
    $auditPoliySubcategoryKey = GetRegistryValue $path $name
    $auditPolicySubcategory = IsForceAuditPoliySubcategoryEnabeled $auditPoliySubcategoryKey

    # Check if Sysmon is installed and running as a service
    $sysmonService = GetService("Sysmon*")
    $sysmon = IsSysmonInstalled $sysmonService

    # Check if CAPI2 is enabled and has a minimum log size of 4MB
    $capi2 = GetCAPI2
    $capi2Result = IsCAPI2Enabled $capi2 $CAPI2LogSize

    $resultCollection = MergeHashtables $auditPolicies $auditPolicySubcategory $sysmon $capi2Result

    WriteXML $resultCollection $OnlineExportPath

    GetEventLogsAndExport $OnlineExportPath
    GetApplicationAndServiceLogs $OnlineExportPath
    $eventLogsDone = ImportCompareExport $ImportPath $OnlineExportPath
    if ($eventLogsDone) {
        VisualizeAll $ImportPath $OnlineExportPath
    }
    
}

Function OfflineAuditPolicies ($ImportPath, $ExportPath) {
    $rsopResult = GetAuditPolicies $ImportPath
    $auditPolicies = AnalyseAuditPolicies $rsopResult
    WriteXML $auditPolicies $ExportPath
    VisualizeAuditPolicies $ExportPath
}

Function OfflineEventLogs ($ImportPath, $ExportPath) {
    $eventLogsDone = ImportCompareExport $ImportPath $ExportPath
    if ($eventLogsDone) {
        VisualizeAll $ExportPath
    }
}

Function Offline ($ImportPath, $ExportPath) {
    $rsopResult = GetAuditPolicies $ImportPath
    $auditPolicies = AnalyseAuditPolicies $rsopResult
    WriteXML $auditPolicies $ExportPath
    $eventLogsDone = ImportCompareExport $ImportPath $ExportPath
    if ($eventLogsDone) {
        VisualizeAll $ExportPath
    }
}

Function CheckExportPath($exportPath) {
    if ($exportPath) {
        if(Test-Path -Path $exportPath) {
            return $exportPath
        } else {
            return $null
        } 
    } else {
        return $PSScriptRoot
    }
}

switch ($PsCmdLet.ParameterSetName) {
    'None' {
        Write-Host "Please define the Script-Mode [-Online|-Offline]" -ForegroundColor Red
        continue
    }
    'Online' {
        Write-Host "Online-Mode"
        $OnlineExportPath = CheckExportPath $OnlineExportPath
        $ImportPath = $OnlineExportPath

        if($OnlineExportPath) {
            Online $OnlineExportPath $CAPI2LogSize
        } else {
            Write-Host "Defined ExportPath $OnlineExportPath does not exist or your user has no access rights" -ForegroundColor Red
        }
        continue
    }
    'Offline' {
        $ExportPath = CheckExportPath $ExportPath
        try {
            $ImportPathExist = Test-Path -Path $ImportPath
        } catch {
            $ImportPathExist = $false
        }            

        if($ExportPath) {
            if(-not $ImportPathExist) {
                Write-Host "Defined ImportPath does not exist or your user has no access rights" -ForegroundColor Red
            } else {
                if ($AuditPolicies) {
                    Write-Host "Offline-Mode AuditPolicies"
                    OfflineAuditPolicies $ImportPath $ExportPath
                } elseif ($EventLogs) {
                    Write-Host "Offline-Mode EventLogs"
                    OfflineEventLogs $ImportPath $ExportPath
                } else {
                    Write-Host "Offline-Mode"
                    Offline $ImportPath $ExportPath
                }
            }
        } else {
            Write-Host "Defined ExportPath $ExportPath does not exist or your user has no access rights" -ForegroundColor Red
        }
        continue
    }
    default {
        return
    }
}