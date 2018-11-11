#Requires -RunAsAdministrator
Remove-Module GetAndAnalyseAuditPolicies
Import-Module .\GetAndAnalyseAuditPolicies.psm1 -Force

$currentPath = (Resolve-Path .\).Path

$auditPolicies = GetAndAnalyseAuditPolicies $currentPath

# Check if setting forcing basic security auditing (Security Settings\Local Policies\Security Options) is ignored to prevent conflicts between similar settings
$path = "HKLM:\System\CurrentControlSet\Control\Lsa"
$name = "SCENoApplyLegacyAuditPolicy"
$auditPoliySubcategoryKey = GetRegistryValue $path $name
$auditPolicySubcategory = IsForceAuditPoliySubcategoryEnabeled $auditPoliySubcategoryKey

# Check if Sysmon is installed and running as a service
$sysmonService = GetService("Sysmon*")
Write-Host $sysmonService
Write-Host $sysmonService.GetType()
$sysmon = IsSysmonInstalled $sysmonService

# Check if CAPI2 is enabled and has a minimum log size of 4MB
$capi2 = GetCAPI2
$capi2Result = IsCAPI2Enabled $capi2 4194304

$resultCollection = MergeHashtables $auditPolicies $auditPolicySubcategory $sysmon $capi2Result

WriteXML $currentPath $resultCollection