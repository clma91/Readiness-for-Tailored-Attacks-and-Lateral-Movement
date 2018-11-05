Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -EnableExit -OutputFile "SourceCode/TestResults.xml" -OutputFormat NUnitXML