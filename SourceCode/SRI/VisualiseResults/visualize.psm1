Add-Type -Path "$PSScriptRoot\itextsharp.dll"
# Import-Module "$PSScriptRoot\PDF.psm1" -Force

function OpenPDF ($exportFolder) {
    $exportPath = $PSScriptRoot + "\results.pdf"
    if ($exportFolder) {
        $exportPath = $exportFolder + "\results.pdf"
    }  
        $pdf = New-Object iTextSharp.text.Document 
        New-PDF -Document $pdf -File $exportPath -TopMargin 20 -BottomMargin 20 -LeftMargin 5 -RightMargin 5 -Author "SRI" | Out-Null
        $pdf.Open()
        Write-Host "Result PDF is created at $exportPath" -ForegroundColor Green
        return $pdf
}

function VisualizeAll($exportFolder) {
    $pdf = OpenPDF $exportFolder
    WriteAuditPolicies $exportFolder
    ToolCanBeDetected $incorrectAudits
    WriteEventLogs $exportFolder
    $pdf.Close()
}

function VisualizeAuditPolicies($exportFolder) {
    $pdf = OpenPDF $exportFolder
    $incorrectAudits = WriteAuditPolicies $exportFolder
    ToolCanBeDetected $incorrectAudits
    $pdf.Close()
}

function VisualizeEventLogs($exportFolder){
    $pdf = OpenPDF $exportFolder
    WriteEventLogs $exportFolder
    $pdf.Close()
}

function CreateAddCellWithColor($content, $R, $G, $B){
    $cell = New-Object iTextSharp.text.pdf.PdfPCell($content)
    $cell.BackgroundColor = New-Object iTextSharp.text.BaseColor($R, $G, $B)
    $table.AddCell($cell) | Out-Null
}

function CreateAddCell($content){
    $cell = New-Object iTextSharp.text.pdf.PdfPCell($content);  
    $table.AddCell($cell) | Out-Null
}

function WriteAuditPolicies($importFolder) {
    $auditpath = $PSScriptRoot + "\resultOfAuditPolicies.xml"
    if ($importFolder) {
        $auditpath = $importFolder + "\resultOfAuditPolicies.xml"
    }    
    [xml] $auditxml = Get-Content $auditpath
    $checklistaudit = @{AuditNonSensitivePrivilegeUse = "SuccessAndFailure"; AuditUserAccountManagement = "Success"; AuditDetailedFileShare = "SuccessAndFailure"; AuditKernelObject = "SuccessAndFailure"; AuditSAM = "SuccessAndFailure"; AuditKerberosAuthenticationService = "SuccessAndFailure"; AuditHandleManipulation = "Success"; AuditRegistry = "SuccessAndFailure"; AuditProcessTermination = "Success"; AuditFileSystem = "SuccessAndFailure"; 'AuditMPSSVCRule-LevelPolicyChange' = "Success"; AuditSpecialLogon = "Success"; AuditLogoff = "Success"; AuditSensitivePrivilegeUse = "SuccessAndFailure"; ersetzen = "SuccessAndFailure"; AuditLogon = "Success"; AuditSecurityGroupManagement = "SuccessAndFailure"; AuditFileShare = "SuccessAndFailure"; AuditKerberosServiceTicketOperations = "SuccessAndFailure"; AuditFilteringPlatformConnection = "Success"; AuditProcessCreation = "Success"; ForceAuditPolicySubcategory = "Enabled"; Sysmon = "InstalledAndRunning"; CAPI2 = "EnabledGoodLogSize"; CAPI2LogSize = 4194304; OtherObjectAccessEvents = "SuccessAndFailure"; }
    
    Add-Title -Document $pdf -Text "AuditPolicies" -Centered | Out-Null
   
    $table = New-Object iTextSharp.text.pdf.PDFPTable(3)
    $table.SpacingBefore = 5
    $table.SpacingAfter = 5

    $myaudits = $auditxml.AuditPolicies.ChildNodes
    CreateAddCell "AuditName"
    CreateAddCell "Target"
    CreateAddCell "Actual"

    foreach ($audit in $myaudits) {
        $incorrectAudits = @()
        $localName = $audit.LocalName
        CreateAddCell $localName
        $checkaudit = $checklistaudit[$localName]
        if ($audit.InnerXml -eq $checkaudit) {
            CreateAddCell $checkaudit
            CreateAddCellWithColor $audit.InnerXml 0 255 0
        } elseif ($audit.InnerXml.startswith("Succ") -and $checkaudit -eq "Success") {
            CreateAddCell $checkaudit
            CreateAddCellWithColor $audit.InnerXml 0 106 0
        } elseif ((-not(!$checkaudit)) -and $checkaudit.GetType().ToString() -eq "System.Int32"){
            $auditint = [uint32]$audit.InnerXml
            if(-not ($auditint -lt $checkaudit)){
                CreateAddCell $checkaudit.ToString()
                CreateAddCellWithColor $audit.InnerXml 0 255 0
            } else{
                CreateAddCell $checkaudit.ToString()
                CreateAddCellWithColor $audit.InnerXml 255 0 0
                $incorrectAudits + $audit.LocalName
            }
        }
        else {
            CreateAddCell $checkaudit
            CreateAddCellWithColor $audit.InnerXml 255 0 0
            $incorrectAudits + $audit.LocalName
        }
    }
    $pdf.Add($table) | Out-Null
    return $incorrectAudits
}

function WriteEventLogs($importFolder){
    $eventpath = $PSScriptRoot + "\resultOfEventLogs.xml"
    if ($importFolder) {
        $eventpath = $importFolder + "\resultOfEventLogs.xml"
    }    
    [xml] $eventxml = Get-Content $eventpath
    Add-Title -Document $pdf -Text "WindowsLogs" -Centered | Out-Null
    $eventswin = $eventxml.Logs.EventLogsID.ChildNodes
    $resulte = @()
    foreach ($e in $eventswin) {
        $resulte += $e.LocalName
        $resulte += $e.InnerXml
    }
    Add-Table -Document $pdf -Dataset $resulte -Cols 2 -Centered | Out-Null

    Add-Title -Document $pdf -Text "AppAndServLogs" -Centered | Out-Null
    $eventsapp = $eventxml.Logs.AppAndServID.ChildNodes
    $resulta = @()
    foreach ($e in $eventsapp) {
        $resulta += $e.LocalName
        $resulta += $e.InnerXml
    }

    Add-Table -Document $pdf -Dataset $resulta -Cols 2 -Centered | Out-Null
}

function ToolCanBeDetected($incorrectAudits){
    $detectables = @()
    $notdetectables = @()
[xml] $auditsbytool = Get-Content "$PSScriptRoot\AuditByTool.xml"
$toolCategories = $auditsbytool.Tool.ChildNodes
foreach($toolCategory in $toolCategories){
     [int]$checknr = 0
   foreach($incorrectAudit in $incorrectAudits){
       if($toolCategory.ChildNodes.InnerXml -contains $incorrectAudit){
           $checknr += 1
       }
   }
  
  if($checknr -gt 0){
      $notdetectables += "`n" + $toolCategory.LocalName
  } else {
    $detectables += $toolCategory.LocalName
  }
 }
 $amoutOfDetecables = $detectables.count
 $text = "With this policies it is possible to detect  $amoutOfDetecables out of 14 attack categories"
 Add-Text -Document $pdf -Text $text | Out-Null
     [String ]$text = "The following attack categories cannot be detected with certainty: $notdetectables"  
 Add-Text -Document $pdf -Text $text | Out-Null
}

Export-ModuleMember -Function visualizeAll, visualizeAuditPolicies, visualizeEventLogs

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#Module PDF.psm1
#
# (C) 2015 Patrick Lambert - http://dendory.net
#

# Import assembly: iTextSharp is from: https://sourceforge.net/projects/itextsharp
Add-Type -Path "$PSScriptRoot\itextsharp.dll"

#
# Function definitions
#

# Set basic PDF settings for the document
Function New-PDF([iTextSharp.text.Document]$Document, [string]$File, [int32]$TopMargin, [int32]$BottomMargin, [int32]$LeftMargin, [int32]$RightMargin, [string]$Author)
{
    $Document.SetPageSize([iTextSharp.text.PageSize]::A4)
    $Document.SetMargins($LeftMargin, $RightMargin, $TopMargin, $BottomMargin)
    try{
        [void][iTextSharp.text.pdf.PdfWriter]::GetInstance($Document, [System.IO.File]::Create($File))
    } catch{
        Write-Host Please close PDF $File -ForegroundColor Red
        Break
    }
    $Document.AddAuthor($Author)
}

# Add a text paragraph to the document, optionally with a font name, size and color
function Add-Text([iTextSharp.text.Document]$Document, [string]$Text, [string]$FontName = "Arial", [int32]$FontSize = 12, [string]$Color = "BLACK")
{
    $p = New-Object iTextSharp.text.Paragraph
    $p.Font = [iTextSharp.text.FontFactory]::GetFont($FontName, $FontSize, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $p.SpacingBefore = 2
    $p.SpacingAfter = 2
    $p.IndentationLeft = 60
    $p.Add($Text)
    $Document.Add($p)
}

# Add a title to the document, optionally with a font name, size, color and centered
function Add-Title([iTextSharp.text.Document]$Document, [string]$Text, [Switch]$Centered, [string]$FontName = "Arial", [int32]$FontSize = 16, [string]$Color = "BLACK")
{
    $p = New-Object iTextSharp.text.Paragraph
    $p.Font = [iTextSharp.text.FontFactory]::GetFont($FontName, $FontSize, [iTextSharp.text.Font]::BOLD, [iTextSharp.text.BaseColor]::$Color)
    if($Centered) { $p.Alignment = [iTextSharp.text.Element]::ALIGN_CENTER }
    $p.SpacingBefore = 5
    $p.SpacingAfter = 5
    $p.Add($Text)
    $Document.Add($p)
}

# Add an image to the document, optionally scaled
function Add-Image([iTextSharp.text.Document]$Document, [string]$File, [int32]$Scale = 100)
{
    [iTextSharp.text.Image]$img = [iTextSharp.text.Image]::GetInstance($File)
    $img.ScalePercent(50)
    $Document.Add($img)
}

# Add a table to the document with an array as the data, a number of columns, and optionally centered
function Add-Table([iTextSharp.text.Document]$Document, [string[]]$Dataset, [int32]$Cols = 3, [Switch]$Centered)
{
    $t = New-Object iTextSharp.text.pdf.PDFPTable($Cols)
    $t.SpacingBefore = 5
    $t.SpacingAfter = 5
    if(!$Centered) { $t.HorizontalAlignment = 0 }
    foreach($data in $Dataset)
    {
        $t.AddCell($data);
    }
    $Document.Add($t)
}