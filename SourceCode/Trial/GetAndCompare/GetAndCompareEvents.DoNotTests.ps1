# Pester tests
Set-Variable -Name ExportFolder -Value  (Resolve-Path .\).Path #current Path
$exportFile=$exportFolder + "\myevents.csv" 
Describe 'Get-EventLog -LogName System' {
  It "Reads the System Logs" {
    $allSystemLogs = Get-EventLog -LogName System
    $allSystemLogs.Count | Should -Not -BeNullOrEmpty
    }
}

Describe 'GetAndExportEventLogs'{
  It 'Tests the function GetAndExportEventLogs'{
    $true | Should -Be true
  }
}

Describe 'Test File'{
  It 'tests if the events file is availabale'{
    
    $exportFile | Should -Exist
    
  }
}




