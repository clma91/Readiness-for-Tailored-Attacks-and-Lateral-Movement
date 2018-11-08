Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -Script "SourceCode\SRI" -OutputFormat NUnitXml -OutputFile "SourceCode\TestResults.xml" -PassThru -ExcludeTag Incomplete