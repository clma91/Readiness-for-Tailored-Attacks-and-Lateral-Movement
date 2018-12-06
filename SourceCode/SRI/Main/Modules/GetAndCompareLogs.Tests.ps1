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
    It 'checks if got app and serve logs from taskscheduler'{
        $events = wevtutil qe Microsoft-Windows-TaskScheduler/Operational /q:"*[System]" /uni:false /f:text
        $events | Should -Not -BeNullOrEmpty
    }

    It 'checks if got app and serve logs from windows remote management'{
        $events = wevtutil qe Microsoft-Windows-WinRM/Operational /q:"*[System]" /uni:false /f:text
        $events | Should -Not -BeNullOrEmpty
    }

    It 'checks if got app and serve logs from terminal services'{
        $events = wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /q:"*[System]" /uni:false /f:text
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
        $resultXML.Logs.EventLogsID | Should -Not -BeNullOrEmpty
        $resultXML.Logs.AppAndServID | Should -Not -BeNullOrEmpty
    }
}
Describe 'Test output if inputpath is wrong'{
    It 'calls a wrong inputpath'{
        $WrongInputPath = "$PSScriptRoot\ThisFolderDoesNotExist"
        $output = ImportCompareExport $WrongInputPath
        $output | Should -Be $false
    }
}
