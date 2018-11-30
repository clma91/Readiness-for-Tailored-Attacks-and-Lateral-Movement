Function GetTargetListAuditPolicies {
    [xml]$targetList = Get-Content ($PSScriptRoot + "\targetlist_auditpolicies.xml")
    $auditSettings = @{}
    foreach($element in $targetList.AuditPolicies.ChildNodes) {
        $values = @($element.InnerXML, $element.priority)
        $auditSettings.Add($element.Localname, $values)
    }
    return $auditSettings
}

$auditSettingSubcategoryNames = GetTargetListAuditPolicies

Write-Host $auditSettingSubcategoryNames.GetType()

foreach($e in $auditSettingSubcategoryNames.GetEnumerator()) {
    Write-Host $e.name.GetType()
    Write-Host $e.value[0].GetType()
    Write-Host $e.value[1].GetType()
    # Write-Host $e[1]
}


