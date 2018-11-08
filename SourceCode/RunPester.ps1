Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
# Invoke-Pester -EnableExit -OutputFile "$PSScriptRoot\TestResults.xml" -OutputFormat NUnitXML
Invoke-Pester -Script "SourceCode\SRI" -OutputFormat NUnitXml -OutputFile "SourceCode\TestResults.xml" -PassThru -ExcludeTag Incomplete