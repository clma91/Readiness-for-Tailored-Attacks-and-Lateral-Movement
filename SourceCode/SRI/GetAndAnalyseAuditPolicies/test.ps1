Function GetTargetListAuditPolicies {
    [xml]$targetList = Get-Content ($PSScriptRoot + "\targetlist_auditpolicies.xml")
    $auditSettingSubcategoryNames = @{}
    foreach($subcategoryname in $targetList.AuditPolicies) {
        $auditSettingSubcategoryNames += $subcategoryname.InnerXml
    }
    return $auditSettingSubcategoryNames
}

$auditSettingSubcategoryNames = GetTargetListAuditPolicies

foreach($a in $auditSettingSubcategoryNames) {
    Write-Host $a
}