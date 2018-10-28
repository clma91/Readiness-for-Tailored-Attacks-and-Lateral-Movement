function isSysmonInstalled {
    $Service = $null
    try {
        $Service = Get-Service -Name Sysmon*
        $result = Get-WinEvent -ListLog *Sysmon* -EA "Stop"
    }
    catch {
        Write-Host 'Sysmon is not installed'
        return $false
    }
    
    if ($Service.Status -ne 'Running') {
        Write-Host 'Sysmon is installed but not running'
        Write-Host $Service.Status
        return $true;
    } else {
        Write-Host 'Sysmon is installed';
        return $true
    }
}

$result = isSysmonInstalled;
Write-Host $result;
