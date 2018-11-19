Add-Type -Path "$PSScriptRoot\itextsharp.dll"
Import-Module "$PSScriptRoot\PDF.psm1"

$currentPath = $PSScriptRoot
$auditpath = $currentPath + "\resultOfAuditPolicies.xml"
$eventpath = $currentPath + "\resultOfEventLogs.xml"
$checklistpath = $currentPath + "\checklistAuditPolicies.xml"
[xml] $auditxml = Get-Content $auditpath
[xml] $eventxml = Get-Content $eventpath
$checklistaudit = @{AuditNonSensitivePrivilegeUse ="SuccessAndFailure"; AuditUserAccountManagement = "SuccessAndFailure"; AuditDetailedFileShare = "SuccessAndFailure"; AuditKernelObject = "SuccessAndFailure"; AuditSAM = "SuccessAndFailure"; AuditKerberosAuthenticationService = "SuccessAndFailure"; AuditHandleManipulation = "SuccessAndFailure";AuditRegistry = "SuccessAndFailure";AuditProcessTermination = "SuccessAndFailure"; AuditFileSystem = "SuccessAndFailure"; 'AuditMPSSVCRule-LevelPolicyChange' = "SuccessAndFailure";AuditSpecialLogon = "SuccessAndFailure";AuditLogoff = "SuccessAndFailure";AuditSensitivePrivilegeUse = "SuccessAndFailure";ersetzen = "SuccessAndFailure";AuditLogon = "SuccessAndFailure";AuditSecurityGroupManagement = "SuccessAndFailure";AuditFileShare = "SuccessAndFailure";AuditKerberosServiceTicketOperations = "SuccessAndFailure";AuditFilteringPlatformConnection = "SuccessAndFailure";AuditProcessCreation = "SuccessAndFailure";ForceAuditPolicySubcategory = "Enabled";Sysmon = "InstalledAndRunning";CAPI2 = "EnabledGoodLogSize";}

$pdf = New-Object iTextSharp.text.Document
Create-PDF -Document $pdf -File "$PSScriptRoot\logic.pdf" -TopMargin 20 -BottomMargin 20 -LeftMargin 5 -RightMargin 5 -Author "SRI"
$pdf.Open()

Add-Title -Document $pdf -Text "AuditPolicies" -Centered

$t = New-Object iTextSharp.text.pdf.PDFPTable(3)
$t.SpacingBefore = 5
$t.SpacingAfter = 5


$myaudits = $auditxml.AuditPolicies.ChildNodes
$result = @()
$c = New-Object iTextSharp.text.pdf.PdfPCell 
$c = New-Object iTextSharp.text.pdf.PdfPCell("AuditName");  
$t.AddCell($c); 
$c = New-Object iTextSharp.text.pdf.PdfPCell("Target");  
$t.AddCell($c);
$c = New-Object iTextSharp.text.pdf.PdfPCell("Actual");  
$t.AddCell($c);

foreach($audit in $myaudits){
    $localName = $audit.LocalName
    $c = New-Object iTextSharp.text.pdf.PdfPCell($localName);  
    $t.AddCell($c);
   $checkaudit = $checklistaudit[$localName]
   if($audit.InnerXml -eq $checkaudit){
    $c = New-Object iTextSharp.text.pdf.PdfPCell($checkaudit);
    $t.AddCell($c);
    $c = New-Object iTextSharp.text.pdf.PdfPCell($audit.InnerXml);
    $c.BackgroundColor = New-Object iTextSharp.text.BaseColor(0, 255, 0);
    $t.AddCell($c)

        
   } else{
    $c = New-Object iTextSharp.text.pdf.PdfPCell($checkaudit);
    $t.AddCell($c);
    $c = New-Object iTextSharp.text.pdf.PdfPCell($audit.InnerXml);
    $c.BackgroundColor = New-Object iTextSharp.text.BaseColor(255, 0, 0);
    $t.AddCell($c)
    }
}
$pdf.Add($t)
$pdf.Close()

