#Requires -RunAsAdministrator

function readResultantSetOfPolicies {
    $now=get-date
    $currentPath = (Resolve-Path .\).Path
    $pathRSOPXML = $currentPath + "\LocalUserAndComputerReport.xml"
    $exportFile = $currentPath + "eventids" + $now.ToString("yyyy-MM-dd---hh-mm-ss") + ".csv"

    enum AuditSettingValues {
        NoAuditing
        Success
        Failure
        SuccessAndFailure
    }
    [AuditSettingValues]$auditSettingValue = 0;
    $auditSettingSubcategoryNames = @("Audit Sensitive Privilege Use","Audit Kerberos Service Ticket Operations","Audit Registry","Audit Security Group Management","Audit File System","Audit Process Termination","Audit Logoff","Audit Process Creation","Audit Filtering Platform Connection","Audit File Share","Audit Kernel Object","Audit MPSSVC Rule-Level Policy Change","Audit Non Sensitive Privilege Use","Audit Logon","Audit SAM","Audit Handle Manipulation","Audit Special Logon","Audit Detailed File Share","Audit Kerberos Authentication Service","Audit User Account Management")

    # Get-GPResultantSetOfPolicy -ReportType Xml -Path  $pathRSOPXML | Out-Null;
    [xml]$rsopResult = Get-Content $pathRSOPXML;

    $auditSettings = $rsopResult.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting

    foreach($auditSettingSubcategoryName in $auditSettingSubcategoryNames) {
        if($auditSettings.SubcategoryName -notcontains $auditSettingSubcategoryName){
            Write-Host "NotConfigured `t`t`t" $auditSettingSubcategoryName
        }
    }

    foreach($auditSetting in $auditSettings) {
        if($auditSetting) {
            try {
                $auditSettingValue = $auditSetting.SettingValue;
            }
            catch {
                $auditSettingValue = 0;
            }
            $auditSubcategoryName = $auditSetting.SubcategoryName 
            
            if ($auditSetting.SettingValue -ne 3) {
                Write-Host $auditSettingValue "`t`t`t" $auditSubcategoryName
            }
        }    
    }
}