Add-Type -Path "$PSScriptRoot\itextsharp.dll"
Import-Module "$PSScriptRoot\PDF.psm1"

$currentPath = (Resolve-Path .\).Path
$auditpath = $currentPath + "\resultOfAuditPolicies.xml"
$xmlpath = $currentPath + "\resultOfEventLogs.xml"
[xml] $auditxml = Get-Content $auditpath
[xml] $eventxml = Get-Content $xmlpath

$pdf = New-Object iTextSharp.text.Document
Create-PDF -Document $pdf -File "$PSScriptRoot\creatpdf.pdf" -TopMargin 20 -BottomMargin 20 -LeftMargin 20 -RightMargin 20 -Author "Patrick"
$pdf.Open()
Add-Title -Document $pdf -Text "Result Set Of Audit Policies" -Centered
$audits = $auditxml.AuditPolicies.ChildNodes
$result = @()
foreach($audit in $audits){
    $result += $audit.LocalName
    $result += $audit.InnerXml
}
Add-Table -Document $pdf -Dataset $result -Cols 2 -Centered
Add-Title -Document $pdf -Text "WindowsLogs" -Centered
$eventswin = $eventxml.Logs.EventLogsID.ChildNodes
$resulte = @()
foreach($e in $eventswin){
    $resulte += $e.LocalName
    $resulte += $e.InnerXml
}
Add-Table -Document $pdf -Dataset $resulte -Cols 2 -Centered

Add-Title -Document $pdf -Text "AppAndServLogs" -Centered
$eventsapp = $eventxml.Logs.AppAndServID.ChildNodes
$resulta = @()
foreach($e in $eventsapp){
    $resulta += $e.LocalName
    $resulta += $e.InnerXml
}
Add-Table -Document $pdf -Dataset $resulta -Cols 2 -Centered
$pdf.Close()
