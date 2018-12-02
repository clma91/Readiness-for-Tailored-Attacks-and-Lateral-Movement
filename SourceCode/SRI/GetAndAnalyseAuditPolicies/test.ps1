Function GetTargetListAuditPolicies {
    [xml]$targetList = Get-Content ($PSScriptRoot + "\targetlist_auditpolicies.xml")
    $auditSettings = @()
    foreach($element in $targetList.AuditPolicies.ChildNodes) {
        if ($element.Localname.StartsWith("Audit")) {
            $auditSettings += $element.Localname 
        }
    }
    return $auditSettings
}

$auditSettingSubcategoryNames = GetTargetListAuditPolicies

Write-Host $auditSettingSubcategoryNames.GetType()

foreach($e in $auditSettingSubcategoryNames) {
    Write-Host $e
}

$auditSettingSubcategoryNames = @("Audit Sensitive Privilege Use", "Audit Kerberos Service Ticket Operations", "Audit Registry", "Audit Security Group Management", "Audit File System", "Audit Process Termination", "Audit Logoff", "Audit Process Creation", "Audit Filtering Platform Connection", "Audit File Share", "Audit Kernel Object", "Audit MPSSVC Rule-Level Policy Change", "Audit Non Sensitive Privilege Use", "Audit Logon", "Audit SAM", "Audit Handle Manipulation", "Audit Special Logon", "Audit Detailed File Share", "Audit Kerberos Authentication Service", "Audit User Account Management", "Audit Other Object Access Events")

Write-Host $auditSettingSubcategoryNames.Count
