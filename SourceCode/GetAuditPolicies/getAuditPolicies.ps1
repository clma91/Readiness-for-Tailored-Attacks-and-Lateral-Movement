$currentPath = (Resolve-Path .\).Path
$pathRSOPXML = $currentPath + "\LocalUserAndComputerReport.html"

Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null

[xml]$rsopResult = Get-Content $pathRSOPXML

$auditSettings = $rsopResult.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting

foreach($auditSetting in $auditSettings) {
    Write-Host $auditSetting.SubcategoryName $auditSetting.SettingValue
}

