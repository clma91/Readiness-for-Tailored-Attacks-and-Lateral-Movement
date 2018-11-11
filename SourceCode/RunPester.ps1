Import-Module "$PSScriptRoot\Pester\Pester.psm1"  
Invoke-Pester -EnableExit -OutputFormat NUnitXml -OutputFile "$PSScriptRoot\TestResults.xml" -PassThru -ExcludeTag Incomplete
# Invoke-Pester -Script "$PSScriptRoot\SRI", "$PSScriptRoot\Trial" -OutputFormat NUnitXml -OutputFile "$PSScriptRoot\TestResults.xml" -PassThru -ExcludeTag Incomplete