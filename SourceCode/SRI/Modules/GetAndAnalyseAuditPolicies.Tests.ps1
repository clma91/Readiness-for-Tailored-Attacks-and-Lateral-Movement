# Pester tests
$currentPath = $PSScriptRoot 
$modulePath = $currentPath + "\GetAndAnalyseAuditPolicies.psm1"
$testFilesPath = $currentPath + "\TestFiles"
Import-Module $modulePath -Force

Write-Host $modulePath

Describe "GetCAPI2" {
    It "should return a XML" {
        $CAPI2 = GetCAPI2
        $CAPI2 | Should BeOfType System.Xml.XmlDocument
    } 
}

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
            $result = IsForceAuditPolicyEnabeled $SCENoApplyLegacyAuditPolicy1

            $result.keys | Should -Contain "ForceAuditPolicySubcategory"
            $result.values | Should -Contain "Enabled"
        }
    }
    Context "registry value SCENoApplyLegacyAuditPolicy = 0" {
        It "checks if function returns ForceAuditPolicySubcategory Enabled" {
            $result = IsForceAuditPolicyEnabeled $SCENoApplyLegacyAuditPolicy0

            $result.keys | Should -Contain "ForceAuditPolicySubcategory"
            $result.values | Should -Contain "Disabled"
        }
    }
}

Describe "IsForceAuditPolicyEnabeled" {
    $AuditPolicyEnabled = [PSCustomObject]@{
        SCENoApplyLegacyAuditPolicy = 1
        PSPath                      = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
        PSParentPath                = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control"
        PSChildName                 = "Lsa"
        PSDrive                     = "HKLM"
        PSProvider                  = "Microsoft.PowerShell.Core\Registry"
    }
    $AuditPolicyDisabled = [PSCustomObject]@{
        SCENoApplyLegacyAuditPolicy = 0
        PSPath                      = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
        PSParentPath                = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control"
        PSChildName                 = "Lsa"
        PSDrive                     = "HKLM"
        PSProvider                  = "Microsoft.PowerShell.Core\Registry"
    }
    $AuditPolicyNotDefined = $null

    It "checks if ISForeAuditFolicyEnabled returns hashtable with ForceAuditPolicySubcategory Enabled" {
        $result = IsForceAuditPolicyEnabeled $AuditPolicyEnabled

        $result | Should BeOfType System.Collections.Hashtable
        $result.keys | should -Contain "ForceAuditPolicySubcategory"
        $result.values | should -Contain "Enabled"
    }
    It "checks if ISForeAuditFolicyEnabled returns hashtable with ForceAuditPolicySubcategory Disabled" {
        $result = IsForceAuditPolicyEnabeled $AuditPolicyDisabled

        $result | Should BeOfType System.Collections.Hashtable
        $result.keys | should -Contain "ForceAuditPolicySubcategory"
        $result.values | should -Contain "Disabled"
    }
    It "checks if ISForeAuditFolicyEnabled returns hashtable with ForceAuditPolicySubcategory NotDefined" {
        $result = IsForceAuditPolicyEnabeled $AuditPolicyNotDefined

        $result | Should BeOfType System.Collections.Hashtable
        $result.keys | should -Contain "ForceAuditPolicySubcategory"
        $result.values | should -Contain "NotDefined"
    }
}

Describe "IsSysmonInstalled" {
    It "checks if Sysmon is installed and running" {
        $result = IsSysmonInstalled

        $result | Should BeOfType System.Collections.Hashtable
        $result.keys | should -Contain "Sysmon"
    }
}

Describe "AnalyseAuditPolicies" {
    [xml]$emptyXML = Get-Content ($testFilesPath + "\empty.xml")
    [xml]$rsopXML = Get-Content ($testFilesPath + "\rsop.xml")
    
    Context "checks if all data is in returned hashtable if empty XML is provided" {
        $result = AnalyseAuditPolicies $emptyXML
        It "checks if empty xml returns hashtable with AuditNonSensitivePrivilegeUse NotConfigured" {
            $result.keys | should -Contain "AuditNonSensitivePrivilegeUse"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditSensitivePrivilegeUse NotConfigured" {
            $result.keys | should -Contain "AuditSensitivePrivilegeUse"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditLogoff NotConfigured" {
            $result.keys | should -Contain "AuditLogoff"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditUserAccountManagement NotConfigured" {
            $result.keys | should -Contain "AuditUserAccountManagement"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditDetailedFileShare NotConfigured" {
            $result.keys | should -Contain "AuditDetailedFileShare"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditSAM NotConfigured" {
            $result.keys | should -Contain "AuditSAM"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditKernelObject NotConfigured" {
            $result.keys | should -Contain "AuditKernelObject"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditKerberosAuthenticationService NotConfigured" {
            $result.keys | should -Contain "AuditKerberosAuthenticationService"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditHandleManipulation NotConfigured" {
            $result.keys | should -Contain "AuditHandleManipulation"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditRegistry NotConfigured" {
            $result.keys | should -Contain "AuditRegistry"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditProcessTermination NotConfigured" {
            $result.keys | should -Contain "AuditProcessTermination"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditFileSystem NotConfigured" {
            $result.keys | should -Contain "AuditFileSystem"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditMPSSVCRule-LevelPolicyChange NotConfigured" {
            $result.keys | should -Contain "AuditMPSSVCRule-LevelPolicyChange"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditSpecialLogon NotConfigured" {
            $result.keys | should -Contain "AuditSpecialLogon"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditFileShare NotConfigured" {
            $result.keys | should -Contain "AuditFileShare"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditProcessCreation NotConfigured" {
            $result.keys | should -Contain "AuditProcessCreation"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditLogon NotConfigured" {
            $result.keys | should -Contain "AuditLogon"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditSecurityGroupManagement NotConfigured" {
            $result.keys | should -Contain "AuditSecurityGroupManagement"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditKerberosServiceTicketOperations NotConfigured" {
            $result.keys | should -Contain "AuditKerberosServiceTicketOperations"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditFilteringPlatformConnection NotConfigured" {
            $result.keys | should -Contain "AuditFilteringPlatformConnection"
            $result.values | should -Contain "NotConfigured"
        }
    }

    Context "checks if all data is in returned hashtable if RSoP-XML is provided" {
        $result = AnalyseAuditPolicies $rsopXML
        It "checks if empty xml returns hashtable with AuditNonSensitivePrivilegeUse Success" {
            $result.keys | should -Contain "AuditNonSensitivePrivilegeUse"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditSensitivePrivilegeUse SuccessAndFailure" {
            $result.keys | should -Contain "AuditSensitivePrivilegeUse"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditLogoff NotConfigured" {
            $result.keys | should -Contain "AuditLogoff"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditUserAccountManagement Success" {
            $result.keys | should -Contain "AuditUserAccountManagement"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditDetailedFileShare NoAuditing" {
            $result.keys | should -Contain "AuditDetailedFileShare"
            $result.values | should -Contain "NoAuditing"
        }
        It "checks if empty xml returns hashtable with AuditSAM SuccessAndFailure" {
            $result.keys | should -Contain "AuditSAM"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditKernelObject NotConfigured" {
            $result.keys | should -Contain "AuditKernelObject"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditKerberosAuthenticationService SuccessAndFailure" {
            $result.keys | should -Contain "AuditKerberosAuthenticationService"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditHandleManipulation Success" {
            $result.keys | should -Contain "AuditHandleManipulation"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditRegistry NotConfigured" {
            $result.keys | should -Contain "AuditRegistry"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditProcessTermination Success" {
            $result.keys | should -Contain "AuditProcessTermination"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditFileSystem SuccessAndFailure" {
            $result.keys | should -Contain "AuditFileSystem"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditMPSSVCRule-LevelPolicyChange Success" {
            $result.keys | should -Contain "AuditMPSSVCRule-LevelPolicyChange"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditSpecialLogon Success" {
            $result.keys | should -Contain "AuditSpecialLogon"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditFileShare SuccessAndFailure" {
            $result.keys | should -Contain "AuditFileShare"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditProcessCreation Success" {
            $result.keys | should -Contain "AuditProcessCreation"
            $result.values | should -Contain "Success"
        }
        It "checks if empty xml returns hashtable with AuditLogon NotConfigured" {
            $result.keys | should -Contain "AuditLogon"
            $result.values | should -Contain "NotConfigured"
        }
        It "checks if empty xml returns hashtable with AuditSecurityGroupManagement SuccessAndFailure" {
            $result.keys | should -Contain "AuditSecurityGroupManagement"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditKerberosServiceTicketOperations SuccessAndFailure" {
            $result.keys | should -Contain "AuditKerberosServiceTicketOperations"
            $result.values | should -Contain "SuccessAndFailure"
        }
        It "checks if empty xml returns hashtable with AuditFilteringPlatformConnection Success" {
            $result.keys | should -Contain "AuditFilteringPlatformConnection"
            $result.values | should -Contain "Success"
        }
    }
}

Describe "MergeHashtables" {
    $FirstHashTable = @{
        key1 = "value1" 
        key2 = "value2"
    }
    $SecondHashTable = @{
        key3 = "value3" 
        key4 = "value4"
    }
    It "checks if the hashtables are merged correctly" {
        $Result = MergeHashtables $FirstHashTable $SecondHashTable

        $Result.keys | should -Contain "key1"
        $Result.keys | should -Contain "key2"
        $Result.keys | should -Contain "key3"
        $Result.keys | should -Contain "key4"

        $Result.values | should -Contain "value1"
        $Result.values | should -Contain "value2"
        $Result.values | should -Contain "value3"
        $Result.values | should -Contain "value4"
    }
    It "checks if MergeHashtables without input returns an hashtable which is NULL and has empty keys and values" {
        $Result = MergeHashtables

        $Result.keys | should -BeNullOrEmpty 
        $Result.values | should -BeNullOrEmpty 
    }
}

Describe "GetAuditSettingValues" {
    $TargetAuditSettings = @("AuditNonSensitivePrivilegeUse", "AuditOtherObjectAccessEvents", "AuditUserAccountManagement")
    $AuditSettings = @{
        "AuditNonSensitivePrivilegeUse" = 3 
        "AuditOtherObjectAccessEvents" = 1 
        "AuditUserAccountManagement" = 1
    }
    $ResultCollection = @{
        "AuditOtherObjectAccessEvents" = "Success"
        "AuditUserAccountManagement" = "Success"
        "AuditNonSensitivePrivilegeUse" = "SuccessAndFailure"
    }

    It "checks if returned result collection is correct" {
        $Result = GetAuditSettingValues $AuditSettings $TargetAuditSettings
        $ResultCollection.Count | Should -Be $Result.Count
    }

    $AuditSettings = @{}

    It "chcks if returned result collection is NULL" {
        $Result = GetAuditSettingValues $AuditSettings $TargetAuditSettings
        $Result | Should -BeNullOrEmpty
    }
}

Describe "WriteXML" {
    $ResultCollection = @{
        AuditNonSensitivePrivilegeUse = "SuccessAndFailure"
        AuditOtherObjectAccessEvents = "SuccessAndFailure"
    }

    It "checks WriteXML without input writes no XML-file" {
        WriteXML
        $XMLPath = "$PSScriptRoot\result_audit_policies.xml"
        Test-Path -LiteralPath $XMLPath | Should -Be $false
    }

    It "checks if result_audit_policies.xml is written" {
        $CurrentPath = $PSScriptRoot
        WriteXML $ResultCollection $CurrentPath
        $XMLPath = "$CurrentPath\result_audit_policies.xml"
        
        Test-Path -LiteralPath $XMLPath | Should -Be $true     
        Remove-Item $XMLPath 
    }
}

Describe "GetAuditPoliciesTargetList" {
    $ResultCollection = @("AuditNonSensitivePrivilegeUse", "AuditOtherObjectAccessEvents", "AuditUserAccountManagement", "AuditProcessTermination", "AuditSAM", "AuditKerberosAuthenticationService", "AuditHandleManipulation", "AuditRegistry", "AuditKerberosServiceTicketOperations", "AuditFileSystem", "AuditLogon", "AuditSpecialLogon", "AuditMPSSVCRule-LevelPolicyChange", "AuditLogoff", "AuditDetailedFileShare", "AuditSensitivePrivilegeUse", "AuditKernelObject", "AuditSecurityGroupManagement", "AuditFileShare", "AuditFilteringPlatformConnection", "AuditProcessCreation")

    It "checks if returned result collection is correct" {
        $Result = GetAuditPoliciesTargetList
        $Result | Should -Be $ResultCollection
    }
}

Describe "CompareToTargetList" {
    $AuditSettings = @{}
    $TargetAuditSettings = @("AuditNonSensitivePrivilegeUse", "AuditOtherObjectAccessEvents", "AuditUserAccountManagement", "AuditProcessTermination", "AuditSAM", "AuditKerberosAuthenticationService", "AuditHandleManipulation", "AuditRegistry", "AuditKerberosServiceTicketOperations", "AuditFileSystem", "AuditLogon", "AuditSpecialLogon", "AuditMPSSVCRule-LevelPolicyChange", "AuditLogoff", "AuditDetailedFileShare", "AuditSensitivePrivilegeUse", "AuditKernelObject", "AuditSecurityGroupManagement", "AuditFileShare", "AuditFilteringPlatformConnection", "AuditProcessCreation")
    $ResultCollection = @{
        "AuditNonSensitivePrivilegeUse" = "NotConfigured"
        "AuditOtherObjectAccessEvents" = "NotConfigured"
        "AuditUserAccountManagement" = "NotConfigured"
        "AuditProcessTermination" = "NotConfigured"
        "AuditSAM" = "NotConfigured"
        "AuditKerberosAuthenticationService" = "NotConfigured"
        "AuditHandleManipulation" = "NotConfigured"
        "AuditRegistry"  = "NotConfigured"
        "AuditKerberosServiceTicketOperations" = "NotConfigured"
        "AuditFileSystem" = "NotConfigured"
        "AuditLogon" = "NotConfigured"
        "AuditSpecialLogon" = "NotConfigured"
        "AuditMPSSVCRule-LevelPolicyChange" = "NotConfigured"
        "AuditLogoff"  = "NotConfigured"
        "AuditDetailedFileShare" = "NotConfigured"
        "AuditSensitivePrivilegeUse" = "NotConfigured"
        "AuditKernelObject" = "NotConfigured"
        "AuditSecurityGroupManagement" = "NotConfigured"
        "AuditFileShare" = "NotConfigured"
        "AuditFilteringPlatformConnection" = "NotConfigured"
        "AuditProcessCreation" = "NotConfigured"
    }

    It "checks if returned result collection is filled with NotConfigured if an empty hashtable is given" {
        $Result = CompareToTargetList $AuditSettings $TargetAuditSettings
        $Result.Count | Should -BeLikeExactly $ResultCollection.Count
    }
}