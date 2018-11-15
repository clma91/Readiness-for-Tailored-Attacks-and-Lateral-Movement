#Requires -RunAsAdministrator
<#
.SYNOPSIS
    System Readiness Inspector (SRI) checks the readiness for tailored attacks and lateral movement detection
.DESCRIPTION
    The Description of the SRI...
.PARAMETER Online
    Checks the readiness of the current local system
.PARAMETER Offline
    Checks the readiness for a system of the provided files
    Parameter "ImportPath" must be defined
.PARAMETER ImportPath
    The following files x.csv, y.csv, rsop.xml must remain at the ImportPath
.PARAMETER ExportPath
    Defines where the results should be stored
.PARAMETER OnlineExportPath
    Defines where the results should be stored
.PARAMETER LogSize
    Defines the LogSize of CAPI2 (default is 4194304 = 4MB). Zero will be matched as default.
    4MB = 4194304Bytes = 4 * 1024 * 1024Bytes
    Reference: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749296(v=ws.10)#capi2-diagnostics-in-windows-vista
.EXAMPLE
    C:\PS> ./sri.ps1 -Online
    - Run the System Readiness Inspector locally
    - Results will be written to the current path of execution
    - The CAPI2 log size will set to default (4MB)
.EXAMPLE
    C:\PS> ./sri.ps1 -Online C:/ExportSRI/
    - Run the System Readiness Inspector locally
    - Results will be written to the given path (in this example: C:/ExportSRI/)
    - The CAPI2 log size will set to default (4MB)
.EXAMPLE
    C:\PS> ./sri.ps1 -Online C:/ExportSRI/ 5242880
    - Run the System Readiness Inspector locally
    - Results will be written to the given path (in this example: C:/ExportSRI/)
    - The CAPI2 log size will bet overwritten to the given value (in this example: 5242880 = 5MB)
.NOTES
    Authors: Lukas Kellenberger, Claudio Mattes
    Date:   December 21, 2018
#>

[CmdletBinding(DefaultParametersetName='None')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Online", Position=0]
    [switch]
    $Online,

    [Parameter(Mandatory = $false, ParameterSetName = "Online", Position=1)]
    [String]
    $OnlineExportPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline", Position=0)]
    [switch]
    $Offline,

    # [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=1, HelpMessage="What type of export file do you want to create? Valid choices are CSV, XML, CLIXML."))]
    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=1)]
    [switch]
    $AuditPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=1)]
    [switch]
    $EventLogs,

    [Parameter(Mandatory = $true, ParameterSetName = "Offline", Position=2)]
    [String]
    $ImportPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Offline", Position=3)]
    [String]
    $ExportPath,

    [Parameter(Mandatory = $false)]
    [int]
    $LogSize
)
Import-Module .\GetAndAnalyseAuditPolicies.psm1 -Force

switch ($PsCmdLet.ParameterSetName) {
    'None' {
        Write-Host "Please define the Script-Mode [-Online|-Offline] -ForegroundColor Red
    }
    'Online' {
        if([string]::IsNullOrEmpty($OnlineExportPath)) {
            $OnlineExportPath = $PSScriptRoot
        }
        Write-Host Online
        Write-Host $OnlineExportPath
        Write-Host $LogSize
    }
    'Offline' {

        Write-Host $ImportPath
        Write-Host $ExportPath

        if ($AuditPolicies) {
            Write-Host "Offline-Mode AuditPolicies"
        } elseif ($EventLogs) {
            Write-Host "Offline-Mode EventLogs"
        } else {
            Write-Host "Offline-Mode"
        }
    }
    Default {
        return
    }
}

