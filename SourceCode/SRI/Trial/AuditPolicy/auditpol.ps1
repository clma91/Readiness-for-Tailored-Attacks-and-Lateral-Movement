#Requires -RunAsAdministrator

$NeededAuditPolicies = 

$Test = auditpol /get /subcategory:"Logon","Logoff","Special Logon","File System","Registry","Kernel Object","SAM","Handle Manipulation","File Share","Filtering Platform Connection","Detailed File Share","Non Sensitive Privilege Use","Sensitive Privilege Use","Process Creation","Process Termination","MPSSVC Rule-Level Policy Change","Security Group Management","User Account Management","Kerberos Service Ticket Operations","Kerberos Authentication Service";
Write-Output $Test[4]
Write-Output $Test[6]
Write-Output $Test[8]
Write-Output $Test[11]
Write-Output $Test[13]
Write-Output $Test[15]
Write-Output $Test[17]
Write-Output $Test[19]
Write-Output $Test[21]
Write-Output $Test[23]
Write-Output $Test[25]
Write-Output $Test[28]
Write-Output $Test[30]
Write-Output $Test[33]
Write-Output $Test[35]