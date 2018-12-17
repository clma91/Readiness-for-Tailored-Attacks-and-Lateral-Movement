#pester tests
$azurePath = $PSScriptRoot 

$currentPath = $azurePath
$modulePath = $currentPath + "\GetAndCompareLogs.psm1"

Import-Module $modulePath -Force

Describe 'read Get-EventLogs'{
    It 'checks if got windowslogs from system'{
        $events = Get-EventLog -LogName System
        $events | Should -Not -BeNullOrEmpty
    }

    It 'checks if got windowslogs from security'{
        $events = Get-EventLog -LogName Security
        $events | Should -Not -BeNullOrEmpty
    }
}

Describe 'read App and Service Logs'{
    It 'checks if got eventlogs from security'{
        $events = wevtutil qe Microsoft-Windows-WinRM/Operational /q:"*[System]" /uni:false /f:text
        $events | Should -Not -BeNullOrEmpty
    }

    It 'checks if got app and serve logs from terminal services'{
        $events = wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /q:"*[System]" /uni:false /f:text
        $events | Should -Not -BeNullOrEmpty
    }
}

Describe 'check function GetApplicationAndServiceLog'{
    $IdsForLocalSessionManager = (21, 24)

    It 'checks the function for TerminalServices-LocalSessionManager'{
        $IdsForLocalSessionManager = (21, 24)
        $events = GetApplicationAndServiceLog $IdsForLocalSessionManager "TerminalServices-LocalSessionManager"
        $events | Should -Not -BeNullOrEmpty
    }
}

Describe 'check function GetEventLogsAndExport'{
    It 'checks function GetEventLogsAndExport'{
        $exportFolder = "$PSScriptRoot\TestFiles"
        GetEventLogsAndExport $exportFolder
        $exportedFile = $exportFolder + "\eventlogs.csv"
        $exportedFile | Should -Exist
        $testLogs = Get-Content $exportedFile
        $testLogs.Count | Should -BeGreaterThan 1
    }
}

Describe 'check function GetApplicationAndServiceLogs'{
    It 'checks function GetEventLogsAndExport'{
        $exportFolder = "$PSScriptRoot\TestFiles"
        GetApplicationAndServiceLogs $exportFolder
        $exportedFile = $exportFolder + "\appandservlogs.csv"
        $exportedFile | Should -Exist
        $testLogs = Get-Content $exportedFile
        $testLogs | Should -BeLike '"EventID"*'
    }
}
Describe 'Test function ImportCompareExport'{
    It 'calls the function and loads a test-xml'{
        $importFolder = "$PSScriptRoot\TestFiles"
        $exportFolder = "$PSScriptRoot\TestFiles"

        ImportCompareExport $importFolder $exportFolder

        $exportedFile = $exportFolder + "\result_event_logs.xml"
        [xml]$resultXML = Get-Content $exportedFile
        $resultXML.Logs.WindowsLogs | Should -Not -BeNullOrEmpty
        $resultXML.Logs.AppAndServLogs | Should -Not -BeNullOrEmpty
    }
}
Describe 'Test output if inputpath is wrong'{
    It 'calls a wrong inputpath'{
        $WrongInputPath = "$PSScriptRoot\ThisFolderDoesNotExist"
        $output = ImportCompareExport $WrongInputPath
        $output | Should -Be $false
    }
}
