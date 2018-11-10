#Requires -RunAsAdministrator
Import-Module .\GetAndAnalyseAuditPolicies.psm1 -Force

$currentPath = (Resolve-Path .\).Path
$resultXML = $currentPath + "\resultOfAuditPolicies.xml"
$xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null)
$xmlWriter.Formatting = "Indented"
$xmlWriter.Indentation = 1
$XmlWriter.IndentChar = "`t"
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteStartElement("AuditPolicies")

GetAndAnalyseAuditPolicies $currentPath $xmlWriter 

# Check if setting forcing basic security auditing (Security Settings\Local Policies\Security Options) is ignored to prevent conflicts between similar settings
IsForceAuditPoliySubcategoryEnabeled $xmlWriter

# Check if Sysmon is installed and running as a service
IsSysmonInstalled $xmlWriter

# Check if CAPI2 is enabled and has a minimum log size of 4MB
IsCAPI2Enabled $xmlWriter 

$xmlWriter.WriteEndElement()
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()

# WriteXML