function isSysmonInstalled {
    $SystemRoot = "$env:systemroot"
    $PathSysmon = $SystemRoot + '\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx';

    if(![System.IO.File]::Exists($PathSysmon)){
        Write-Host 'Sysmon is not installed';
        return $false;
    } else {
        Write-Host 'Sysmon is installed';
        return $true
    }
}

$result = isSysmonInstalled;
Write-Host $result;