# Pester tests
$localPath = (Resolve-Path .\).Path
$azurePath = $PSScriptRoot 

$currentPath = $azurePath
$modulePath = $currentPath + "\GetAndAnalyseAuditPolicies.psm1"
Import-Module $modulePath -Force

Write-Host $modulePath

Describe "IsCAPI2Enabled" {
    $testFilesPath = $currentPath + "\TestFiles"
    $logSize = 4194304
    [xml]$capi2Disabled = Get-Content ($testFilesPath + "\capi2Disabled.xml")
    [xml]$capi2EnabledBadLogSize = Get-Content ($testFilesPath + "\capi2EnabledBadLogSize.xml")
    [xml]$capi2EnabledGoodLogSize = Get-Content ($testFilesPath + "\capi2EnabledGoodLogSize.xml")

    Context "xml with disabled CAPI2" {
        It "checks if function returns Disable" {
            $capi2Result = IsCAPI2Enabled $capi2Disabled $logSize
            $capi2Result.keys | Should -Contain "CAPI2"
            $capi2Result.values | Should -Contain "Disabled"
        }
    }
    Context "xml with enabled CAPI2 but bad log size of 1048576" {
        It "checks if function returns EnabledBadLogSize" {
            $capi2Result = IsCAPI2Enabled $capi2EnabledBadLogSize $logSize
            $capi2Result.keys | Should -Contain "CAPI2"
            $capi2Result.values | Should -Contain "EnabledBadLogSize"
        }
        It "checks if function returns LogSize of 1048576" {
            $capi2Result = IsCAPI2Enabled $capi2EnabledBadLogSize $logSize
            $capi2Result.keys | Should -Contain "CAPI2LogSize"
            $capi2Result.values | Should -Contain "1048576"
        }
    }
    Context "xml with enabled CAPI2 but good log size of 4980736" {
        It "checks if function returns EnabledGoodLogSize" {
            $capi2Result = IsCAPI2Enabled $capi2EnabledGoodLogSize $logSize
            $capi2Result.keys | Should -Contain "CAPI2"
            $capi2Result.values | Should -Contain "EnabledGoodLogSize"
        }
        It "checks if function returns LogSize of 4980736" {
            $capi2Result = IsCAPI2Enabled $capi2EnabledGoodLogSize $logSize
            $capi2Result.keys | Should -Contain "CAPI2LogSize"
            $capi2Result.values | Should -Contain "4980736"
        }
    }
}

Describe "IsForceAuditPoliySubcategoryEnabeled" {
    $SCENoApplyLegacyAuditPolicy1 = @{SCENoApplyLegacyAuditPolicy=1;}
    $SCENoApplyLegacyAuditPolicy0 = @{SCENoApplyLegacyAuditPolicy=0;}

    Context "registry value SCENoApplyLegacyAuditPolicy = 1" {
        It "checks if function returns ForceAuditPolicySubcategory Enabled" {
            $result = IsForceAuditPoliySubcategoryEnabeled $SCENoApplyLegacyAuditPolicy1

            $result.keys | Should -Contain "ForceAuditPolicySubcategory"
            $result.values | Should -Contain "Enabled"
        }
    }
    Context "registry value SCENoApplyLegacyAuditPolicy = 0" {
        It "checks if function returns ForceAuditPolicySubcategory Enabled" {
            $result = IsForceAuditPoliySubcategoryEnabeled $SCENoApplyLegacyAuditPolicy0

            $result.keys | Should -Contain "ForceAuditPolicySubcategory"
            $result.values | Should -Contain "Disabled"
        }
    }
}

Describe "IsSysmonInstalled" {
    $sysmon64ServiceRunning = @{DisplayName="Sysmon64";Status="Running";}
    $sysmonServiceRunning = @{DisplayName="Sysmon";Status="Running";}
    $sysmon64ServiceStopped = @{DisplayName="Sysmon64";Status="Stopped";}
    $sysmonServiceStopped = @{DisplayName="Sysmon";Status="Stopped";}
    $sysmonNotInstalled = $null

    Context "Sysmon64" {
        It "checks if Sysmon64 is installed and running" {
            $result = IsSysmonInstalled $sysmon64ServiceRunning

            $result.keys | should -Contain "Sysmon"
            $result.values | should -Contain "InstalledAndRunning"
        }

        It "checks if Sysmon64 is installed but not running" {
            $result = IsSysmonInstalled $sysmon64ServiceStopped

            $result.keys | should -Contain "Sysmon"
            $result.values | should -Contain "InstalledNotRunning"
        }

        It "checks if Sysmon64 is not installed" {
            $result = IsSysmonInstalled $sysmonNotInstalled

            $result.keys | should -Contain "Sysmon"
            $result.values | should -Contain "NotInstalled"
        }
    }

    Context "Sysmon" {
        
    }
}