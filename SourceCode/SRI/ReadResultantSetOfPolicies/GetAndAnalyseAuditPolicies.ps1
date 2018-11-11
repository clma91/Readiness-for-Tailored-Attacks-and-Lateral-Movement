#Requires -RunAsAdministrator
Remove-Module GetAndAnalyseAuditPolicies
Import-Module .\GetAndAnalyseAuditPolicies.psm1 -Force

$currentPath = (Resolve-Path .\).Path

$auditPolicies = GetAndAnalyseAuditPolicies $currentPath

# Check if setting forcing basic security auditing (Security Settings\Local Policies\Security Options) is ignored to prevent conflicts between similar settings
$auditPolicySubcategory = IsForceAuditPoliySubcategoryEnabeled

# Check if Sysmon is installed and running as a service
$sysmon = IsSysmonInstalled 

# Check if CAPI2 is enabled and has a minimum log size of 4MB
$capi2 = IsCAPI2Enabled 4194304

$resultCollection = Merge-Hashtables $auditPolicies $auditPolicySubcategory $sysmon $capi2

WriteXML $currentPath $resultCollection