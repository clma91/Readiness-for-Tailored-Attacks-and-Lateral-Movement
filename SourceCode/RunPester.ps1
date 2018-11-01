Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -EnableExit -OutputFile "./artifacts/TestResults.xml" -OutputFormat NUnitXm