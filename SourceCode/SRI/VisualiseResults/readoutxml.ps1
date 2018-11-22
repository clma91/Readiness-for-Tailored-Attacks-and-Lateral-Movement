[xml]$test = Get-Content "$PSScriptRoot\IDsByTool.xml"
Write-Host $test
$Tools = $test.Tool.ChildNodes
foreach($tool in $Tools){
    write-host $tool.LocalName
    $Logs = $tool.ChildNodes
    foreach($log in $Logs){
        write-host $log.LocalName
        $IDs = $log.ChildNodes
foreach($id in $IDs){
Write-Host $id.InnerXml
        }
    }
}