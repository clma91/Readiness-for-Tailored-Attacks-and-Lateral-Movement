function GetEventLogsAndExport{
    Write-Host Collecting EventLogs
    $StartMs = (Get-Date).Ticks
    foreach($log in $args[0]) #$LogNames
    {
        $args[1] += Get-EventLog -LogName $log #$events
    }
    $EndMs = (Get-Date).Ticks
    Write-Host It took $($EndMs - $StartMs) ticks, or $(($EndMs - $StartMs) /10000000) secs. to get the EventLogs
    Write-Host Done collecting

$args[1]| Select EventID -Unique |Export-CSV $args[2] -NoTypeInfo -Encoding UTF8  #EXPORT || $events / $exportfile
Write-Host Done exporting to $args[2] #$exportcsv
}
function GetApplicationAndServiceLogs {

    $args[0] += '"EventID"' #appAndServLogs
    
    foreach($id in $args[1]){ #tasksch
    if(wevtutil qe Microsoft-Windows-TaskScheduler/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
        $args[0] += '"' + $id + '"'
         }
    }
    
    foreach($id in $args[2]){ #winrm
        if(wevtutil qe Microsoft-Windows-WinRM/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
            $args[0] += '"' + $id + '"'
            }
    }
    
        foreach($id in $args[3]){ #terminalserv
            if(wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /q:"*[System[(EventID="$id")]]" /uni:false /f:text){
                $args[0] += '"' + $id + '"'
                }
        }

    $args[0] | Out-File -FilePath $args[4] #applicationAndServiceLogs outputpath
}

function ImportCompareExport{

    $importEventLogs = $args[0] #$exportfileEventLogs
    
    $args[1] = Import-Csv $importEventLogs -Encoding UTF8 #$myEventLogs

    Write-Host Comparing Found EventLogs to Checklist
    
    $args[2].Formatting = "Indented" #$xmlWriter
    $args[2].Indentation = 1
    $args[2].IndentChar = "`t"
    $args[2].WriteStartDocument()
    $args[2].WriteStartElement("Logs")
    $args[2].WriteStartElement("EventLogsID")
        
       foreach($id in $args[3]){ #$eventLogIdsToCheck
           if($args[1] | where {$_.EventID -eq $id}){ #$myEvents
            $args[2].WriteStartElement("EventID" +$id)#$xmlWriter
            $args[2].WriteValue("present")
            $args[2].WriteEndElement()
                }
                else{
                    $args[2].WriteStartElement("EventID" +$id)#$xmlWriter
                    $args[2].WriteValue("missing")
                    $args[2].WriteEndElement()
                }
        }
    $args[2].WriteEndElement() #$xmlWriter
    #$args[2].WriteEndDocument()

    $importAppAndServLogs = $args[4] #exportfileAppAndServLogs

    $args[5] = Import-Csv $importAppAndServLogs -Encoding UTF8 #myAppAndServLogs

    Write-Host Comparing Found AppAndServLogs
    #$args[2].WriteStartDocument()
    $args[2].WriteStartElement("AppAndServID")

    foreach($id in $args[6]){ #appAndServLogIdsToCheck
        if($args[5] | where {$_.EventID -eq $id}){ #$myEvents
            $args[2].WriteStartElement("EventID" + $id)#$xmlWriter
            $args[2].WriteValue("present")
            $args[2].WriteEndElement()
                }
                else{
                    $args[2].WriteStartElement("EventID" + $id)#$xmlWriter
                    $args[2].WriteValue("missing")
                    $args[2].WriteEndElement()
                }
    }
    Write-Host Done comparing

    Write-Host Exporting XML
    $args[2].WriteEndElement()
    $args[2].WriteEndDocument()
    $args[2].Flush()
    $args[2].Close()
    
    Write-Host Done!

    Remove-Item $importEventLogs
    Remove-Item $importAppAndServLogs
}

Export-ModuleMember -Function GetEventLogsAndExport
Export-ModuleMember -Function GetApplicationAndServiceLogs
Export-ModuleMember -Function ImportCompareExport


