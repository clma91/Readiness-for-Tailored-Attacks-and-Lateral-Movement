Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -Script ".\SRI" -OutputFormat NUnitXml -OutputFile ".\TestResults.xml" -PassThru -ExcludeTag Incomplete