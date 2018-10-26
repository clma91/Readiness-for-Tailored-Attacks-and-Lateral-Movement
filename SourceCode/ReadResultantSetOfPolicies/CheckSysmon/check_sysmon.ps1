function isSysmonInstalled {
    $PathSysmon = $env:systemroot + '\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx';
    $ServiceName = 'Sysmon64'
    $arrService = Get-Service -Name $ServiceName
    
    if(![System.IO.File]::Exists($PathSysmon)){
        Write-Host 'Sysmon is not installed';
        return $false;
    } elseif ($arrService.Status -ne 'Running') {
        Write-Host 'Sysmon is installed but not running'
        return $true;
    } else {
        Write-Host 'Sysmon is installed';
        return $true
    }
}

$result = isSysmonInstalled;
Write-Host $result;
