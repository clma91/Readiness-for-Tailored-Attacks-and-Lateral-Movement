Add-Type -Path "$PSScriptRoot\itextsharp.dll"

Function GetAuditPoliciesTargetList {
    [xml]$TargetList = Get-Content ("$PSScriptRoot\..\Config\targetlist_auditpolicies.xml")
    $AuditSettings = @{}
    foreach ($Element in $TargetList.AuditPolicies.ChildNodes) {
        $Values = @($Element.InnerXML, $Element.priority)
        $AuditSettings.Add($Element.Localname, $Values)
    }
    return $AuditSettings
}
Function OpenPDF ([String] $ExportFolder) {
    $ExportPath = "$PSScriptRoot\results.pdf"
    if ($ExportFolder) {
        $ExportPath = "$ExportFolder\results.pdf"
    }  
    $Pdf = New-Object iTextSharp.text.Document 
    New-PDF -Document $Pdf -File $ExportPath -TopMargin 20 -BottomMargin 20 -LeftMargin 5 -RightMargin 5 -Author "SRI" | Out-Null
    $Pdf.Open()
    return $Pdf
}

Function VisualizeAll([String] $ExportFolder) {
    $TableAudit = New-Object iTextSharp.text.pdf.PDFPTable(4)
    $Pdf = OpenPDF $ExportFolder
    $IncorrectAudits = WriteAuditPolicies $ExportFolder
    ToolCanBeDetected $IncorrectAudits
    $Pdf.Add($TableAudit) | Out-Null
    WriteEventLogs $ExportFolder
    $Pdf.Close()
    Write-Host "Result PDF is created at $ExportFolder"
}

Function VisualizeAuditPolicies([String] $ExportFolder) {
    $TableAudit = New-Object iTextSharp.text.pdf.PDFPTable(4)
    $Pdf = OpenPDF $ExportFolder
    $IncorrectAudits = WriteAuditPolicies $ExportFolder
    ToolCanBeDetected $IncorrectAudits
    $Pdf.Add($TableAudit) | Out-Null
    $Pdf.Close()
    Write-Host "Result PDF is created at $ExportFolder"
}

Function VisualizeEventLogs([String] $ExportFolder) {
    $Pdf = OpenPDF $ExportFolder
    WriteEventLogs $ExportFolder
    $Pdf.Close()
    Write-Host "Result PDF is created at $ExportFolder"
}

Function CreateAddCellWithColor([String] $Content, [int] $R, [int] $G, [int] $B) {
    $P = New-Object iTextSharp.text.Paragraph
    $P.Font = [iTextSharp.text.FontFactory]::GetFont("Arial", 10, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $P.Add($Content)
    $Cell = New-Object iTextSharp.text.pdf.PdfPCell($P)
    $Cell.BackgroundColor = New-Object iTextSharp.text.BaseColor($R, $G, $B)
    $TableAudit.AddCell($Cell) | Out-Null
}

Function CreateAddCell([String] $Content) {
    $P = New-Object iTextSharp.text.Paragraph
    $P.Font = [iTextSharp.text.FontFactory]::GetFont("Arial", 10, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $P.Add($Content)
    $Cell = New-Object iTextSharp.text.pdf.PdfPCell($P);
    $TableAudit.AddCell($Cell) | Out-Null
}

Function WriteAuditPolicies([String] $ImportFolder) {
    $AuditPath = "$PSScriptRoot\result_audit_policies.xml"
    if ($ImportFolder) {
        $AuditPath = "$ImportFolder\result_audit_policies.xml"
    }    
    [xml] $AuditXml = Get-Content $AuditPath
    $AuditChecklist = GetAuditPoliciesTargetList
    
    Add-Title -Document $Pdf -Text "AuditPolicies" -Centered | Out-Null
   
    $TableAudit.SpacingBefore = 20
    $TableAudit.SpacingAfter = 20
    $MyAudits = $AuditXml.AuditPolicies.ChildNodes
    CreateAddCell "AuditName"
    CreateAddCell "Target"
    CreateAddCell "Actual"
    CreateAddCell "Prio"

    foreach ($Audit in $MyAudits) {
        $IncorrectAudits = @()
        $LocalName = $Audit.LocalName
        CreateAddCell $LocalName
        $CheckAudit = $AuditChecklist[$LocalName]
        $CheckAuditValue = $CheckAudit[0]
        $CheckAuditPrio = $CheckAudit[1]
        if ($Audit.InnerXml -eq $CheckAuditValue) {
            CreateAddCell $CheckAuditValue
            CreateAddCellWithColor $Audit.InnerXml 0 255 0
        }
        elseif ($Audit.InnerXml.startswith("Succ") -and $CheckAuditValue -eq "Success") {
            CreateAddCell $CheckAuditValue
            CreateAddCellWithColor $Audit.InnerXml 0 106 0
        }
        elseif ((-not(!$CheckAuditValue)) -and $CheckAuditValue.GetType() -eq [System.Int32]) {
            $AuditInt = [uint32]$Audit.InnerXml
            if (-not ($AuditInt -lt $CheckAuditValue)) {
                CreateAddCell $CheckAuditValue.ToString()
                CreateAddCellWithColor $Audit.InnerXml 0 255 0
            }
            else {
                CreateAddCell $CheckAuditValue.ToString()
                CreateAddCellWithColor $Audit.InnerXml 255 0 0
                $IncorrectAudits + $Audit.LocalName
            }
        }
        else {
            CreateAddCell $CheckAuditValue
            CreateAddCellWithColor $Audit.InnerXml 255 0 0
            $IncorrectAudits + $Audit.LocalName
        }
        CreateAddCell $CheckAuditPrio 
    }
    return $IncorrectAudits
}

Function ReadOutLogs([xml] $EventXml, [String] $Logname) {
    Add-Title -Document $Pdf -Text $Logname -Centered | Out-Null
    $Events = $EventXml.Logs.$Logname.ChildNodes
    $Result = @()
    foreach ($Element in $Events) {
        $Result += $Element.LocalName
        $Result += $Element.InnerXml
    }
    Add-Table -Document $Pdf -Dataset $Result -Cols 2 -Centered | Out-Null
}

Function WriteEventLogs([String] $ImportFolder) {
    $EventPath = "$PSScriptRoot\result_event_logs.xml"
    if ($ImportFolder) {
        $EventPath = "$ImportFolder\result_event_logs.xml"
    }    
    $Pdf.NewPage() | Out-Null
    [xml] $EventXml = Get-Content $EventPath
    ReadOutLogs $EventXml "WindowsLogs"
    ReadOutLogs $EventXml "AppAndServLogs"
}

Function ToolCanBeDetected([Array] $IncorrectAudits) {
    $Detectables = @()
    $NotDetectableCategories = @()
    [xml] $AuditsByCategory = Get-Content "$PSScriptRoot\..\Config\audit_by_category.xml"
    $ToolCategories = $AuditsByCategory.Category.ChildNodes
    foreach ($ToolCategory in $ToolCategories) {
        [int]$CheckNr = 0
        $CausingAudit = @()
        $CausingAuditText = ""
        foreach ($IncorrectAudit in $IncorrectAudits) {
            if ($ToolCategory.ChildNodes.InnerXml -contains $IncorrectAudit) {
                $CheckNr += 1
                $CausingAudit += $IncorrectAudit
            }
        }
    
        if ($CheckNr -gt 0) {
            for ($i = 0; $i -lt $CausingAudit.Count; $i++) {
                if($i -lt ($CausingAudit.Count - 1)){
                    $CausingAuditText += $CausingAudit[$i].ToString() + ", "
                } else {
                    $CausingAuditText += $CausingAudit[$i].ToString()
                }
            }
            $NotDetectableCategories += "`n" + "- " + $ToolCategory.LocalName + " (" + $CausingAuditText + ")"
        } else {
            $Detectables += $ToolCategory.LocalName
        }
    }
    $AmoutOfDetecables = $Detectables.count
    $Text = "With this policies it is possible to detect $AmoutOfDetecables out of 14 attack categories"
    Add-Text -Document $Pdf -Text $Text | Out-Null
    [String ]$text = "The following attack categories cannot be detected with certainty: $NotDetectableCategories"  
    Add-Text -Document $Pdf -Text $Text | Out-Null
}

Export-ModuleMember -Function visualizeAll, visualizeAuditPolicies, visualizeEventLogs, GetAuditPoliciesTargetList

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
        Write-Host "Please close PDF $File" -ForegroundColor Red
        Break
    }
    $Document.AddAuthor($Author)
}

# Add a text paragraph to the document, optionally with a font name, size and color
Function Add-Text([iTextSharp.text.Document]$Document, [string]$Text, [string]$FontName = "Arial", [int32]$FontSize = 10, [string]$Color = "BLACK") {
    $P = New-Object iTextSharp.text.Paragraph
    $P.Font = [iTextSharp.text.FontFactory]::GetFont($FontName, $FontSize, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
    $P.SpacingBefore = 2
    $P.SpacingAfter = 2
    $P.IndentationLeft = 60
    $P.Add($Text)
    $Document.Add($P)
}

# Add a title to the document, optionally with a font name, size, color and centered
Function Add-Title([iTextSharp.text.Document]$Document, [string]$Text, [Switch]$Centered, [string]$FontName = "Arial", [int32]$FontSize = 16, [string]$Color = "BLACK") {
    $P = New-Object iTextSharp.text.Paragraph
    $P.Font = [iTextSharp.text.FontFactory]::GetFont($FontName, $FontSize, [iTextSharp.text.Font]::BOLD, [iTextSharp.text.BaseColor]::$Color)
    if ($Centered) { $P.Alignment = [iTextSharp.text.Element]::ALIGN_CENTER }
    $P.SpacingBefore = 15
    $P.SpacingAfter = 15
    $P.Add($Text)
    $Document.Add($P)
}
# Add an image to the document, optionally scaled
Function Add-Image([iTextSharp.text.Document]$Document, [string]$File, [int32]$Scale = 100) {
    [iTextSharp.text.Image]$img = [iTextSharp.text.Image]::GetInstance($File)
    $img.ScalePercent(50)
    $Document.Add($img)
}

# Add a table to the document with an array as the data, a number of columns, and optionally centered
Function Add-Table([iTextSharp.text.Document]$Document, [string[]]$Dataset, [int32]$Cols = 3, [Switch]$Centered) {
    $t = New-Object iTextSharp.text.pdf.PDFPTable($Cols)
    $t.SpacingBefore = 5
    $t.SpacingAfter = 5
    
    if (!$Centered) { $t.HorizontalAlignment = 0 }
    foreach ($data in $Dataset) {
        $P = New-Object iTextSharp.text.Paragraph
        $P.Font = [iTextSharp.text.FontFactory]::GetFont("Arial", 10, [iTextSharp.text.Font]::NORMAL, [iTextSharp.text.BaseColor]::$Color)
        $P.Add($data)
        $Cell = New-Object iTextSharp.text.pdf.PdfPCell($P)
        $t.AddCell($Cell);
    }
    $Document.Add($t)
}