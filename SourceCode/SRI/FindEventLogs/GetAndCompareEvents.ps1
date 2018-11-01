Set-Variable -Name LogNames -Value @("Application", "System", "Security")
Set-Variable -Name ExportFolder -Value  (Resolve-Path .\).Path #current Path
Set-Variable -Name idsToCheck (6, 21, 24, 102, 104, 106, 129, 169, 200, 201, 4624, 4634, 4648, 4656, 4658, 4660, 4661, 4663, 4672, 4673, 4688, 4689, 4690, 4720, 4726, 4728, 4729, 4768,4769, 4946, 5140, 5142, 5144, 5145, 5154, 5156, 7036, 7045, 8222, 20001)  

$events = New-Object System.Collections.ArrayList
$resultMyEvents = New-Object System.Collections.ArrayList

$exportFile=$exportFolder + "\myevents.csv" 
$exportResultFile=$exportFolder + "\resultmyevents.txt" 
Write-Host Collecting EventLogs
foreach($log in $LogNames)
{
    $events += get-eventlog -LogName $log 
}
Write-Host Done collecting
$events| Select EventID |Export-CSV $exportFile -NoTypeInfo -Encoding UTF8  #EXPORT
Write-Host Done exporting to $exportFile

$importFile = $exportFile

$myEvents = Import-Csv $importFile -Encoding UTF8
Write-Host Comparing Found Logs to Checklist

$resultXML = "resultOfEventLogs.xml"
$xmlWriter = New-Object System.XMl.XmlTextWriter($resultXML,$Null)
$xmlWriter.Formatting = "Indented"
$xmlWriter.Indentation = 1
$XmlWriter.IndentChar = "`t"
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteStartElement("EventID")
    
   foreach($id in $idsToCheck){
       if($myEvents | where {$_.EventID -eq $id}){ 
          $resultMyEvents.add("present: " + $id + ";")
          $xmlWriter.WriteStartElement($id)
          $xmlWriter.WriteValue("present")
          $xmlWriter.WriteEndElement()
            }
            else{
                $resultMyEvents.add("missing: " + $id + ";")
                $xmlWriter.WriteStartElement($id)
                $xmlWriter.WriteValue("missing")
                $xmlWriter.WriteEndElement()
            }
    }
Write-Host Done comparing
Write-Host Exporting to $exportResultFile

$resultMyEvents| Out-File $exportResultFile
$xmlWriter.WriteEndElement()
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()

Write-Host Done!