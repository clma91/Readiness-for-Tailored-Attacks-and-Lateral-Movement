Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -Script "$PSScriptRoot\SRI\Modules" -OutputFormat NUnitXml -OutputFile "$PSScriptRoot\TestResults.xml" -PassThru -ExcludeTag Incomplete