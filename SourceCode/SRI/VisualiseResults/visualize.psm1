Add-Type -Path "$PSScriptRoot\itextsharp.dll"
# Import-Module "$PSScriptRoot\PDF.psm1" -Force
$tableAudit = New-Object iTextSharp.text.pdf.PDFPTable(4)
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
    $incorrectAudits = WriteAuditPolicies $exportFolder
    ToolCanBeDetected $incorrectAudits
    $pdf.Add($tableAudit) | Out-Null
    WriteEventLogs $exportFolder
    
    $pdf.Close()
}

function VisualizeAuditPolicies($exportFolder) {
    $pdf = OpenPDF $exportFolder
    $incorrectAudits = WriteAuditPolicies $exportFolder
    ToolCanBeDetected $incorrectAudits
    $pdf.Close()
}

function VisualizeEventLogs($exportFolder) {
    $pdf = OpenPDF $exportFolder
    WriteEventLogs $exportFolder
    $pdf.Close()
}

function CreateAddCellWithColor($content, $R, $G, $B) {
    $p = New-Object iTextSharp.text.Paragraph
    $p.Font = [iTextSharp.text.FontFactory]::GetFont("Arial", 10, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $p.Add($content)
    $cell = New-Object iTextSharp.text.pdf.PdfPCell($p)
    $cell.BackgroundColor = New-Object iTextSharp.text.BaseColor($R, $G, $B)
    $tableAudit.AddCell($cell) | Out-Null
}

function CreateAddCell($content) {
    $p = New-Object iTextSharp.text.Paragraph
    $p.Font = [iTextSharp.text.FontFactory]::GetFont("Arial", 10, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $p.Add($content)
    $cell = New-Object iTextSharp.text.pdf.PdfPCell($p);
    $tableAudit.AddCell($cell) | Out-Null
}

function WriteAuditPolicies($importFolder) {
    $auditPath = $PSScriptRoot + "\resultOfAuditPolicies.xml"
    if ($importFolder) {
        $auditPath = $importFolder + "\resultOfAuditPolicies.xml"
    }    
    [xml] $auditXml = Get-Content $auditPath
    $auditChecklist = @{AuditNonSensitivePrivilegeUse = @("SuccessAndFailure", "Low"); AuditUserAccountManagement = @("Success", "Low"); AuditDetailedFileShare = @("SuccessAndFailure", "Low"); AuditKernelObject = @("SuccessAndFailure", "High"); AuditSAM = @("SuccessAndFailure", "Low"); AuditKerberosAuthenticationService = @("SuccessAndFailure", "Low"); AuditHandleManipulation = @("Success", "Low"); AuditRegistry = @("SuccessAndFailure", "High"); AuditProcessTermination = @("Success", "High"); AuditFileSystem = @("SuccessAndFailure", "High"); 'AuditMPSSVCRule-LevelPolicyChange' = @("Success", "Low"); AuditSpecialLogon = @("Success", "Low"); AuditLogoff = @("Success", "Medium"); AuditSensitivePrivilegeUse = @("SuccessAndFailure", "Low"); AuditLogon = @("Success", "Medium"); AuditSecurityGroupManagement = @("SuccessAndFailure", "Low"); AuditFileShare = @("SuccessAndFailure", "Low"); AuditKerberosServiceTicketOperations = @("SuccessAndFailure", "Low"); AuditFilteringPlatformConnection = @("Success", "Low"); AuditProcessCreation = @("Success", "High"); ForceAuditPolicySubcategory = @("Enabled", "-"); Sysmon = @("InstalledAndRunning", "High"); CAPI2 = @("EnabledGoodLogSize", "-"); CAPI2LogSize = @(4194304, "-"); AuditOtherObjectAccessEvents = @("SuccessAndFailure", "Low")}

    Add-Title -Document $pdf -Text "AuditPolicies" -Centered | Out-Null
   
    $tableAudit.SpacingBefore = 20
    $tableAudit.SpacingAfter = 20
    $myaudits = $auditXml.AuditPolicies.ChildNodes
    CreateAddCell "AuditName"
    CreateAddCell "Target"
    CreateAddCell "Actual"
    CreateAddCell "Prio"

    foreach ($audit in $myaudits) {
        $incorrectAudits = @()
        $localName = $audit.LocalName
        CreateAddCell $localName
        $checkaudit = $auditChecklist[$localName]
        $checkauditvalue = $checkaudit[0]
        $checkauditprio = $checkaudit[1]
        if ($audit.InnerXml -eq $checkauditvalue) {
            CreateAddCell $checkauditvalue
            CreateAddCellWithColor $audit.InnerXml 0 255 0
        }
        elseif ($audit.InnerXml.startswith("Succ") -and $checkauditvalue -eq "Success") {
            CreateAddCell $checkauditvalue
            CreateAddCellWithColor $audit.InnerXml 0 106 0
        }
        elseif ((-not(!$checkauditvalue)) -and $checkauditvalue.GetType() -eq [System.Int32]) {
            $auditint = [uint32]$audit.InnerXml
            if (-not ($auditint -lt $checkauditvalue)) {
                CreateAddCell $checkauditvalue.ToString()
                CreateAddCellWithColor $audit.InnerXml 0 255 0
            }
            else {
                CreateAddCell $checkauditvalue.ToString()
                CreateAddCellWithColor $audit.InnerXml 255 0 0
                $incorrectAudits + $audit.LocalName
            }
        }
        else {
            CreateAddCell $checkauditvalue
            CreateAddCellWithColor $audit.InnerXml 255 0 0
            $incorrectAudits + $audit.LocalName
        }
        CreateAddCell $checkauditprio 
    }
    return $incorrectAudits
}

function WriteEventLogs($importFolder) {
    $eventpath = $PSScriptRoot + "\resultOfEventLogs.xml"
    if ($importFolder) {
        $eventpath = $importFolder + "\resultOfEventLogs.xml"
    }    
    $pdf.NewPage() | Out-Null
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

function ToolCanBeDetected($incorrectAudits) {
    $detectables = @()
    $notdetectables = @()
    $causingAudit = @()
    [xml] $auditsbytool = Get-Content "$PSScriptRoot\AuditByTool.xml"
    $toolCategories = $auditsbytool.Tool.ChildNodes
    foreach ($toolCategory in $toolCategories) {
        [int]$checknr = 0
        foreach ($incorrectAudit in $incorrectAudits) {
            if ($toolCategory.ChildNodes.InnerXml -contains $incorrectAudit) {
                $checknr += 1
                $causingAudit += $incorrectAudit + ", "
            }
        }
    
        if ($checknr -gt 0) {
            $notdetectables += "`n" + "- " + $toolCategory.LocalName + "(" + $causingAudit + ")"
        } else {
            $detectables += $toolCategory.LocalName
        }
        $causingAudit = ""
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
Function New-PDF([iTextSharp.text.Document]$Document, [string]$File, [int32]$TopMargin, [int32]$BottomMargin, [int32]$LeftMargin, [int32]$RightMargin, [string]$Author) {
    $Document.SetPageSize([iTextSharp.text.PageSize]::A4)
    $Document.SetMargins($LeftMargin, $RightMargin, $TopMargin, $BottomMargin)
    try {
        [void][iTextSharp.text.pdf.PdfWriter]::GetInstance($Document, [System.IO.File]::Create($File))
    }
    catch {
        Write-Host Please close PDF $File -ForegroundColor Red
        Break
    }
    $Document.AddAuthor($Author)
}

# Add a text paragraph to the document, optionally with a font name, size and color
function Add-Text([iTextSharp.text.Document]$Document, [string]$Text, [string]$FontName = "Arial", [int32]$FontSize = 10, [string]$Color = "BLACK") {
    $p = New-Object iTextSharp.text.Paragraph
    $p.Font = [iTextSharp.text.FontFactory]::GetFont($FontName, $FontSize, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $p.SpacingBefore = 2
    $p.SpacingAfter = 2
    $p.IndentationLeft = 60
    $p.Add($Text)
    $Document.Add($p)
}

# Add a title to the document, optionally with a font name, size, color and centered
function Add-Title([iTextSharp.text.Document]$Document, [string]$Text, [Switch]$Centered, [string]$FontName = "Arial", [int32]$FontSize = 16, [string]$Color = "BLACK") {
    $p = New-Object iTextSharp.text.Paragraph
    $p.Font = [iTextSharp.text.FontFactory]::GetFont($FontName, $FontSize, [iTextSharp.text.Font]::BOLD, [iTextSharp.text.BaseColor]::$Color)
    if ($Centered) { $p.Alignment = [iTextSharp.text.Element]::ALIGN_CENTER }
    $p.SpacingBefore = 20
    $p.SpacingAfter = 20
    $p.Add($Text)
    $Document.Add($p)
}
# Add an image to the document, optionally scaled
function Add-Image([iTextSharp.text.Document]$Document, [string]$File, [int32]$Scale = 100) {
    [iTextSharp.text.Image]$img = [iTextSharp.text.Image]::GetInstance($File)
    $img.ScalePercent(50)
    $Document.Add($img)
}

# Add a table to the document with an array as the data, a number of columns, and optionally centered
function Add-Table([iTextSharp.text.Document]$Document, [string[]]$Dataset, [int32]$Cols = 3, [Switch]$Centered) {
    $t = New-Object iTextSharp.text.pdf.PDFPTable($Cols)
    $t.SpacingBefore = 5
    $t.SpacingAfter = 5
  
    
    if (!$Centered) { $t.HorizontalAlignment = 0 }
    foreach ($data in $Dataset) {
        $p = New-Object iTextSharp.text.Paragraph
        $p.Font = [iTextSharp.text.FontFactory]::GetFont("Arial", 10, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
        $p.Add($data)
        $cell = New-Object iTextSharp.text.pdf.PdfPCell($p)
        $t.AddCell($cell);
    }
    $Document.Add($t)
}