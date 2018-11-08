Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -EnableExit -OutputFile "$PSScriptRoot\TestResults.xml" -OutputFormat NUnitXML