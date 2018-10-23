# Update with whatever method you use to generate your host list
$hostNames = @("localhost")
$psExec = "C:\Temp\PSExec.exe"
$auditPol = "C:\Windows\System32\AuditPol.exe"
 
$auditPolicy = @()
foreach ($hostName in $hostNames) {
    Write-Host "Processing $hostName" -NoNewline
 
    $ErrorActionPreference = "Continue" # Required for PSExec  
    $auditPolicyString = &$psExec "\\$hostName" -accepteula -n 5 cmd /c $auditPol /get /category:* 2>&1
    $ErrorActionPreference = "Stop"
 
    if ($LastExitCode -ne 0) {
        Write-Host ": Failed"
        # You can parse the ErrorRecord types from $auditPolicyString if you want to get the real error
    } else {
        $thisAuditPolicy = New-Object PSObject -Property @{
            "Host Name" = $hostName
        }
 
        $auditPolicyString | Where { $_ -is [string] -and $_ } <# Remove blank lines #> | Select -Skip 2 <# Headers #> | %{
            # Headers don't have two columns and so don't have two spaces
            if ($_ -like "*  *") {
                # The left and right columns are separated by two spaces, extract into two groups and ignore spaces between them
                $_ -match '  ([a-z, /-]+)  ([a-z, ]+)' | Out-Null
 
                # Add a property for each audit policy
                $thisAuditPolicy | Add-Member -MemberType NoteProperty -Name "$($Matches[1].Trim())" -Value $Matches[2]
            }
        }
 
        $auditPolicy += $thisAuditPolicy
        Write-Host ": Ok"
    }
}

# Output ready for Excel
$auditPolicy | ConvertTo-Csv -NoTypeInformation | Set-Content C:\Temp\AuditPolicy.csv

# Optionally test that every property name is accessible
# $auditPolicy[0].psobject.Properties | Select -ExpandProperty Name | Where { $_ -ne "Host Name" } | %{ &$auditPol /Get /Subcategory:"$_" } 