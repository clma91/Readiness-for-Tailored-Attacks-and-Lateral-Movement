function GetEventLogsAndExport{
    Write-Host Collecting EventLogs
    $StartMs = (Get-Date).Ticks
    foreach($log in $args[0]) #$LogNames
    {
        $args[1] += get-eventlog -LogName $log #$events
    }
    $EndMs = (Get-Date).Ticks
    Write-Host It took $($EndMs - $StartMs) ticks, or $(($EndMs - $StartMs) /10000000) secs. to get the EventLogs
    Write-Host Done collecting

$args[1]| Select EventID -Unique |Export-CSV $args[2] -NoTypeInfo -Encoding UTF8  #EXPORT || $events / $exportfile
Write-Host Done exporting to $args[2] #$exportfile
}

function ImportCompareExport{

    $importFile = $args[0] #$exportfile
    
    $args[1] = Import-Csv $importFile -Encoding UTF8 #$myEvents

    Write-Host Comparing Found Logs to Checklist
    
    $args[2].Formatting = "Indented" #$xmlWriter
    $args[2].Indentation = 1
    $args[2].IndentChar = "`t"
    $args[2].WriteStartDocument()
    $args[2].WriteStartElement("EventID")
        
       foreach($id in $args[3]){ #$idsToCheck
           if($args[1] | where {$_.EventID -eq $id}){ #$myEvents
            $args[2].WriteStartElement($id)#$xmlWriter
            $args[2].WriteValue("present")
            $args[2].WriteEndElement()
                }
                else{
                    $args[2].WriteStartElement($id)#$xmlWriter
                    $args[2].WriteValue("missing")
                    $args[2].WriteEndElement()
                }
        }
    Write-Host Done comparing

    Write-Host Exporting to XML
    $args[2].WriteEndElement() #$xmlWriter
    $args[2].WriteEndDocument()
    $args[2].Flush()
    $args[2].Close()
    
    Write-Host Done!
}

Export-ModuleMember -Function GetEventLogsAndExport
Export-ModuleMember -Function ImportCompareExport


