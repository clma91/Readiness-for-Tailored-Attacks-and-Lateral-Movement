Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -EnableExit -OutputFile ".\TestResults.xml" -OutputFormat NUnitXML