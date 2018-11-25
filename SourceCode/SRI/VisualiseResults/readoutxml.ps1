# [xml]$test = Get-Content "$PSScriptRoot\IDsByTool.xml"
# Write-Host $test
# $Tools = $test.Tool.ChildNodes
# foreach($tool in $Tools){
#     write-host $tool.LocalName
#     $Logs = $tool.ChildNodes
#     foreach($log in $Logs){
#         write-host $log.LocalName
#         $IDs = $log.ChildNodes
# foreach($id in $IDs){
# Write-Host $id.InnerXml
#         }
#     }
# }

[xml]$test = Get-Content "$PSScriptRoot\AuditByTool.xml"

$Tools = $test.Tool.ChildNodes

foreach($tool in $Tools){
    Write-Host ------------------------------------------------------------------------
    Write-Host $tool.LocalName
    Write-Host 
    $audits = $tool.ChildNodes
    foreach($audit in $audits){
        Write-Host $audit.InnerXml 
    }
}