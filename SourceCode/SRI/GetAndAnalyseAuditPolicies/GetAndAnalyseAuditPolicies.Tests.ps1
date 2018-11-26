# Pester tests
$localPath = (Resolve-Path .\).Path
$azurePath = $PSScriptRoot 

$currentPath = $azurePath
$modulePath = $currentPath + "\GetAndAnalyseAuditPolicies.psm1"
$testFilesPath = $currentPath + "\TestFiles"
Import-Module $modulePath -Force

Write-Host $modulePath

Describe "IsCAPI2Enabled" {
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
    }

    Context "Sysmon" {
        It "checks if Sysmon is installed and running" {
            $result = IsSysmonInstalled $sysmonServiceRunning

            $result.keys | should -Contain "Sysmon"
            $result.values | should -Contain "InstalledAndRunning"
        }

        It "checks if Sysmon is installed but not running" {
            $result = IsSysmonInstalled $sysmonServiceStopped

            $result.keys | should -Contain "Sysmon"
            $result.values | should -Contain "InstalledNotRunning"
        }

        It "checks if Sysmon is not installed" {
            $result = IsSysmonInstalled $sysmonNotInstalled

            $result.keys | should -Contain "Sysmon"
            $result.values | should -Contain "NotInstalled"
        }
    }
}

# Describe "AnalyseAuditPolicies" {
#     [xml]$emptyXML = Get-Content ($testFilesPath + "\empty.xml")
#     [xml]$rsopXML = Get-Content ($testFilesPath + "\rsop.xml")
    
#     It "checks if empty xml returns hashtable with AuditNonSensitivePrivilegeUse NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditNonSensitivePrivilegeUse"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditSensitivePrivilegeUse NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditSensitivePrivilegeUse"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditLogoff NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditLogoff"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditUserAccountManagement NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditUserAccountManagement"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditDetailedFileShare NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditDetailedFileShare"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditSAM NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditSAM"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditKernelObject NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditKernelObject"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditKerberosAuthenticationService NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditKerberosAuthenticationService"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditHandleManipulation NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditHandleManipulation"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditRegistry NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditRegistry"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditProcessTermination NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditProcessTermination"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditFileSystem NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditFileSystem"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditMPSSVCRule-LevelPolicyChange NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditMPSSVCRule-LevelPolicyChange"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditSpecialLogon NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditSpecialLogon"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditFileShare NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditFileShare"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditProcessCreation NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditProcessCreation"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditLogon NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditLogon"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditSecurityGroupManagement NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditSecurityGroupManagement"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditKerberosServiceTicketOperations NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditKerberosServiceTicketOperations"
#         $result.values | should -Contain "NotConfigured"
#     }
#     It "checks if empty xml returns hashtable with AuditFilteringPlatformConnection NotConfigured" {
#         $result = AnalyseAuditPolicies $emptyXML

#         $result.keys | should -Contain "AuditFilteringPlatformConnection"
#         $result.values | should -Contain "NotConfigured"
#     }

#     It "checks if rsop xml returns hashtable with all audit-keys NotConfigured, NoAuditing, Success, Failure and SuccessAndFailure" {
#         $result = AnalyseAuditPolicies $rsopXML

#         $result.keys | should -Contain "AuditNonSensitivePrivilegeUse"
#         $result.keys | should -Contain "AuditSensitivePrivilegeUse"
#         $result.keys | should -Contain "AuditLogoff"
#         $result.keys | should -Contain "AuditUserAccountManagement"
#         $result.keys | should -Contain "AuditDetailedFileShare"
#         $result.keys | should -Contain "AuditSAM"
#         $result.keys | should -Contain "AuditKernelObject"
#         $result.keys | should -Contain "AuditKerberosAuthenticationService"
#         $result.keys | should -Contain "AuditHandleManipulation"
#         $result.keys | should -Contain "AuditRegistry"
#         $result.keys | should -Contain "AuditProcessTermination"
#         $result.keys | should -Contain "AuditFileSystem"
#         $result.keys | should -Contain "AuditMPSSVCRule-LevelPolicyChange"
#         $result.keys | should -Contain "AuditSpecialLogon"
#         $result.keys | should -Contain "AuditFileShare"
#         $result.keys | should -Contain "AuditProcessCreation"
#         $result.keys | should -Contain "AuditLogon"
#         $result.keys | should -Contain "AuditSecurityGroupManagement"
#         $result.keys | should -Contain "AuditKerberosServiceTicketOperations"
#         $result.keys | should -Contain "AuditFilteringPlatformConnection"
#         $result.values | should -Contain "NotConfigured"
#         $result.values | should -Contain "NoAuditing"
#         $result.values | should -Contain "Success"
#         $result.values | should -Contain "Failure"
#         $result.values | should -Contain "SuccessAndFailure"
#     }

# }