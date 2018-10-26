$currentPath = (Resolve-Path .\).Path
$pathRSOPXML = $currentPath + "\LocalUserAndComputerReport.xml"
enum AuditSettingValues {
    NoAuditing
    Success
    Failure
    SuccessAndFailure
}
[AuditSettingValues]$auditSettingValue = 0;

$AuditSettingSubcategoryNames = @("Audit Sensitive Privilege Use","Audit Kerberos Service Ticket Operations","Audit Registry","Audit Security Group Management","Audit File System","Audit Process Termination","Audit Logoff","Audit Process Creation","Audit Filtering Platform Connection","Audit File Share","Audit Kernel Object","Audit MPSSVC Rule-Level Policy Change","Audit Non Sensitive Privilege Use","Audit Logon","Audit SAM","Audit Handle Manipulation","Audit Special Logon","Audit Detailed File Share","Audit Kerberos Authentication Service","Audit User Account Management")

Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null;
[xml]$rsopResult = Get-Content $pathRSOPXML;

$auditSettings = $rsopResult.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting

foreach($AuditSettingSubcategoryName in $AuditSettingSubcategoryNames) {
    if($auditSettings.SubcategoryName -notcontains $AuditSettingSubcategoryName){
        Write-Host "NotConfigured `t`t`t" $AuditSettingSubcategoryName
    }
}

foreach($auditSetting in $auditSettings) {
    $auditSettingValue = $auditSetting.SettingValue
    $auditSubcategoryName = $auditSetting.SubcategoryName 
    
    if ($auditSetting.SettingValue -ne 3) {
        Write-Host $auditSettingValue "`t`t`t" $auditSubcategoryName
    }
}