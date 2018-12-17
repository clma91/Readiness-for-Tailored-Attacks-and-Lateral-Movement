# Pester tests
$currentPath = $PSScriptRoot 
$modulePath = $currentPath + "\Visualize.psm1"
$testFilesPath = $currentPath + "\TestFiles"
Import-Module $modulePath -Force

Describe "GetAuditPoliciesTargetList" {
    $ResultCollection = @{
        "AuditNonSensitivePrivilegeUse" = @("SuccessAndFailure", "Low")
        "AuditOtherObjectAccessEvents" = @("SuccessAndFailure", "Low")
        "AuditUserAccountManagement" = @("Success", "Medium")
        "AuditKernelObject" = @("SuccessAndFailure", "High")
        "AuditSAM" = @("SuccessAndFailure", "Low")
        "AuditKerberosAuthenticationService" = @("SuccessAndFailure", "Low")
        "AuditHandleManipulation" = @("Success", "Low")
        "AuditRegistry" = @("SuccessAndFailure", "High") 
        "AuditProcessTermination" = @("Success", "High")
        "AuditFileSystem" = @("SuccessAndFailure", "High")
        "AuditMPSSVCRule-LevelPolicyChange" = @("Success", "Medium")
        "AuditSpecialLogon" = @("Success", "High")
        "Sysmon" = @("InstalledAndRunning", "High")
        "ForceAuditPolicySubcategory" = @("Enabled", "High")
        "CAPI2LogSize" = @("4194304", "Low")
        "AuditFileShare" = @("SuccessAndFailure", "Low")
        "AuditLogoff" = @("Success", "Low")
        "AuditDetailedFileShare" = @("SuccessAndFailure", "Medium")
        "AuditSensitivePrivilegeUse" = @("SuccessAndFailure", "Medium")
        "AuditLogon" = @("SuccessAndFailure", "Medium")
        "AuditSecurityGroupManagement" = @("SuccessAndFailure", "Medium")
        "AuditKerberosServiceTicketOperations" = @("SuccessAndFailure", "Low")
        "CAPI2" = @("EnabledGoodLogSize", "Low")
        "AuditFilteringPlatformConnection" = @("Success", "Low")
        "AuditProcessCreation" = @("Success", "High")
    }

    It "tests if the target list returnes the correct NOF elements" {
        $Result = GetAuditPoliciesTargetList
        $Result.Count | Should -Be $ResultCollection.Count
    } 
    It "tests if the target list returnes the correct elements" {
        $Result = GetAuditPoliciesTargetList
        $Result | Should -BeLikeExactly $ResultCollection
    }
}