Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -CodeCoverage *.ps1 -Path "SourceCode/TestResults.xml" -OutputFormat NUnitXml -OutputFile "$PSScriptRoot\TestResult.xml"