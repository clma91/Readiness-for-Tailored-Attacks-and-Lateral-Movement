#Requires -RunAsAdministrator

<#
.SYNOPSIS
    System Readiness Inspector (SRI) checks the readiness for tailored attacks and lateral movement detection
.DESCRIPTION
    .
.PARAMETER Path
    The path to the .
.PARAMETER LiteralPath
    Specifies a path to one or more locations. Unlike Path, the value of 
    LiteralPath is used exactly as it is typed. No characters are interpreted 
    as wildcards. If the path includes escape characters, enclose it in single
    quotation marks. Single quotation marks tell Windows PowerShell not to 
    interpret any characters as escape sequences.
.EXAMPLE
    C:\PS> 
    <Description of example>
.NOTES
    Author: Lukas Kellenberger, Claudio Mattes
    Date:   December 21, 2018
#>

Write-Host Test