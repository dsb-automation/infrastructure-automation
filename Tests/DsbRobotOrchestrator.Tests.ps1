$humioToken = $env:HUMIO_INGEST_TOKEN

$here = (Split-Path -Parent $MyInvocation.MyCommand.Path)
$parentDirectory = (Get-Item $here).parent.FullName
$moduleName = "DsbRobotOrchestration"

If (Get-Module $moduleName) {
    Remove-Module $moduleName -Force
}
Import-Module "$parentDirectory\$moduleName\$moduleName.psm1" -Force


# =============== Begin Tests ==================
Describe 'Start-Log' {

    It 'Creates new directory if logpath does not exist' {
        $logPath = "C:/fake/path"
        $logName = "fake-logname.log"
        $joinedPath = Join-Path -Path $logPath -ChildPath $logName
        
        Mock -Verifiable -CommandName Test-Path -ModuleName $moduleName -MockWith { return $false }
        Mock -Verifiable -CommandName Test-Path { return $true } -ModuleName $moduleName -ParameterFilter { $Path -eq $joinedPath }
        Mock -Verifiable -CommandName New-Item -ModuleName $moduleName

        Start-Log -LogPath $logPath -LogName $logName
        Assert-MockCalled New-Item 1 -ParameterFilter { $ItemType -eq "Directory" } -ModuleName $moduleName
    }

    It 'Creates file if file at file at logpath does not exist' {
        $logPath = "C:/fake/path"
        $logName = "fake-logname.log"
        $joinedPath = Join-Path -Path $logPath -ChildPath $logName
        
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $logPath } -MockWith { return $true } -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $joinedPath } -MockWith { return $false } -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $joinedPath -and $PSBoundParameters['Verbose'] -eq $true } -MockWith { return $true } -ModuleName $moduleName
        Mock -Verifiable -CommandName New-Item -ModuleName $moduleName

        Start-Log -LogPath $logPath -LogName $logName
        Assert-MockCalled New-Item -Exactly 1 -ParameterFilter { $ItemType -eq "File" } -ModuleName $moduleName
    }

    It 'Throws error if logfile not found after created' {
        $logPath = "C:/fake/path"
        $logName = "fake-logname.log"
        $joinedPath = Join-Path -Path $logPath -ChildPath $logName
        
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $logPath } -MockWith { return $true } -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $joinedPath } -MockWith { return $false } -ModuleName $moduleName
        Mock -Verifiable -CommandName New-Item -ModuleName $moduleName

        { Start-Log -LogPath $logPath -LogName $logName } | Should -Throw 
    }
}

Describe 'Format-LogMessage' {
    It 'Correctly formats a string' {
        $pcName = $env:computername
        $logPath = "logpath"
        $message = "Something went terribly wrong"
        $environment = "dev"
        $severity = "Error"
        $date = "blah"

        Mock -Verifiable -CommandName Get-Date -MockWith { return "blah" } -ModuleName $moduleName
        
        $expectedStringError = "$date $severity message=$message env=$environment timeStamp=$date level=$severity pcName=$pcName logfile=$logPath"
        Write-Host $expectedStringError
        $logString = Format-LogMessage -LogPath $logPath -Message $message -Environment $environment -Severity $severity
        Write-Host $logString
        Assert-VerifiableMock
        $logString | Should -BeExactly $expectedStringError 
    }
}

Describe 'Remove-OldFilebeatFolders' {
    It 'Calls remove-item if original filebeats dirs exists' {
        $FilebeatVersion = "7.2.0"
        $unzippedFile = "C:\Program Files\filebeat-$FilebeatVersion-windows-x86"
        $programFileFilebeat = "C:\Program Files\Filebeat"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $unzippedFile } -MockWith { return $true } -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName -ParameterFilter { $Path -eq $unzippedFile -and $PSBoundParameters['Force'] -eq $true }
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $programFileFilebeat } -MockWith { return $true } -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName -ParameterFilter { $Path -eq $programFileFilebeat -and $PSBoundParameters['Force'] -eq $true }

        Remove-OldFilebeatFolders -FullLogPath 'fakelog\path' -FilebeatVersion $FilebeatVersion
        Assert-MockCalled Remove-Item -Exactly 1 { $Path -eq  $unzippedFile -and $PSBoundParameters['Force'] -eq $true } -ModuleName $moduleName
        Assert-MockCalled Remove-Item -Exactly 1 { $Path -eq  $programFileFilebeat -and $PSBoundParameters['Force'] -eq $true } -ModuleName $moduleName
    }
}

Describe 'Get-FilebeatConfig' {

    It 'Calls remove-item for old filebeat config' {
        $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml -and $PSBoundParameters['Force'] -eq $true }
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml } -MockWith { return $true }

        Get-FilebeatConfig -FullLogPath 'fakelog\path'
        Assert-MockCalled Remove-Item -Exactly 1 { $Path -eq  $filebeatYaml -and $PSBoundParameters['Force'] -eq $true } -ModuleName $moduleName
    }

    It 'Calls download-file with the correct params' {
        $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"
        $configUri = "https://github.com/dsb-automation/infrastructure-automation/blob/master/filebeat.yml"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml -and $PSBoundParameters['Force'] -eq $true }
        Mock -Verifiable -CommandName Test-Path -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml } -MockWith { return $true }
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName 

        Get-FilebeatConfig -FullLogPath 'fakelog\path'
        Assert-MockCalled Download-File 1 { $Url -eq $configUri -and $OutPath -eq $filebeatYaml -and $FullLogPath -eq 'fakelog\path' } -ModuleName $moduleName
    }

    It 'Throws error if yaml file not found' {
        $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml -and $PSBoundParameters['Force'] -eq $true }
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml } -MockWith { return $false }

       { Get-FilebeatConfig -FullLogPath 'fakelog\path' } | Should -Throw
    }
}

Describe 'Get-Filebeat' {

    It 'Throws error when provided invalid filebeat version' {
        $logPath = "C:/fake/logpathfake-filebeat.log"
        $downloadPath = "C:/fake/installpath"
        $wrongVersion = "7.1.0"

        { Get-FilebeatZip -FullLogPath $logPath -DownloadPath $downloadPath -FilebeatVersion $wrongVersion } | Should -Throw
    }

    It 'Removes previously downloaded filebeat if it exists' {
        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $downloadPath = "C:\fake\download"
        $filebeatZip = "filebeat.zip"
        $fullDownloadPath = Join-Path -Path $downloadPath -ChildPath $filebeatZip
        $correctVersion = "7.2.0"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $fullDownloadPath } -MockWith { return $true } -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName 
        Mock -Verifiable -CommandName Expand-Archive -ModuleName $moduleName
        Mock -Verifiable -CommandName Rename-Item -ModuleName $moduleName

        Get-FilebeatZip -FullLogPath $logPath -DownloadPath $downloadPath -FilebeatVersion $correctVersion
        Assert-MockCalled Remove-Item -Exactly 1 { $Path -eq $fullDownloadPath -and $PSBoundParameters['Recurse'] -eq $true } -ModuleName $moduleName
    }

    It 'Renames the original zip file to Filebeat' {
        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $downloadPath = "C:\fake\download"
        $filebeatZip = "filebeat.zip"
        $fullDownloadPath = Join-Path -Path $downloadPath -ChildPath $filebeatZip
        $correctVersion = "7.2.0"
        $unzippedFile = "C:\Program Files\filebeat-$correctVersion-windows-x86"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $fullDownloadPath } -ModuleName $moduleName
        Mock -Verifiable -CommandName Expand-Archive -ModuleName $moduleName
        Mock -Verifiable -CommandName Rename-Item -ModuleName $moduleName

        Get-FilebeatZip -FullLogPath $logPath -DownloadPath $downloadPath -FilebeatVersion $correctVersion
        Assert-MockCalled Rename-Item 1 { $Path -eq $unzippedFile -and $NewName -eq 'Filebeat' } -ModuleName $moduleName
    }

    It 'Correctly makes the download-file request' {
        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $fullLogPath = Join-Path -Path $logPath -ChildPath -$logName
        $downloadPath = "C:\fake\invokeweb"
        $filebeatZip = "filebeat.zip"
        $fullDownloadPath = Join-Path -Path $downloadPath -ChildPath $filebeatZip
        $correctVersion = "7.2.0"
        $url = "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-$correctVersion-windows-x86.zip"
        $unzippedFile = "C:\Program Files\filebeat-$correctVersion-windows-x86"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $fullDownloadPath } -MockWith { return $false } -ModuleName $moduleName
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName
        Mock -Verifiable -CommandName Expand-Archive -ModuleName $moduleName
        Mock -Verifiable -CommandName Rename-Item -ModuleName $moduleName

        Get-FilebeatZip -FullLogPath $fullLogPath -DownloadPath $downloadPath -FilebeatVersion $correctVersion
        Assert-MockCalled Download-File -Exactly 1 { $Url -eq $url -and $OutPath -eq $fullDownloadPath -and $FullLogPath -eq $fullLogPath }  -ModuleName $moduleName
    }

    It 'Correctly makes the expand-archive request' {
        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $downloadPath = "C:\fake\expandarchive"
        $filebeatZip = "filebeat.zip"
        $fullDownloadPath = Join-Path -Path $downloadPath -ChildPath $filebeatZip
        $newPath = Join-Path -Path $downloadPath -ChildPath 'Filebeat'
        $correctVersion = "7.2.0"

        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $fullDownloadPath } -MockWith { return $false } -ModuleName $moduleName
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName
        Mock -Verifiable -CommandName Expand-Archive -ModuleName $moduleName
        Mock -Verifiable -CommandName Rename-Item -ModuleName $moduleName

        Get-FilebeatZip -FullLogPath $logPath -DownloadPath $downloadPath -FilebeatVersion $correctVersion
        Assert-MockCalled Expand-Archive -Exactly 1 { $Path -eq $fullDownloadPath -and $DestinationPath -eq 'C:\Program Files' -and $PSBoundParameters['Force'] -eq $true } -ModuleName $moduleName
    }

    It 'Renames the expanded filebeat zip' {
        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $downloadPath = "C:\fake\expandarchive"
        $filebeatZip = "filebeat.zip"
        $fullDownloadPath = Join-Path -Path $downloadPath -ChildPath $filebeatZip
        $newPath = Join-Path -Path $downloadPath -ChildPath 'Filebeat'
        $correctVersion = "7.2.0"
        $unzippedFile = "C:\Program Files\filebeat-$correctVersion-windows-x86"


        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Test-Path -ParameterFilter { $Path -eq $fullDownloadPath } -MockWith { return $false } -ModuleName $moduleName
        Mock -Verifiable -CommandName Download-File -ModuleName $moduleName
        Mock -Verifiable -CommandName Expand-Archive -ModuleName $moduleName
        Mock -Verifiable -CommandName Rename-Item -ModuleName $moduleName

        Get-FilebeatZip -FullLogPath $logPath -DownloadPath $downloadPath -FilebeatVersion $correctVersion
        Assert-MockCalled Rename-Item 1 -ModuleName $moduleName { $Path -eq $unzippedFile -and $NewName -eq 'Filebeat' }
    }
}

Describe 'Confirm-FilebeatServiceRunning' {
    It 'Returns true when service is labeled as running' {
        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -ModuleName $moduleName Get-WmiObject { [PSCustomObject]@{ State = "Running" } }

        $result = Confirm-FilebeatServiceRunning -FullLogPath "logpath"
        $result | Should -Be $true
    }

    It 'Returns false in all other cases' {
        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -ModuleName $moduleName 'Get-WmiObject' { }

        $result = Confirm-FilebeatServiceRunning -FullLogPath "logpath"
        $result | Should -Be $false
    }
}

Describe 'Start-FilebeatService' {
    Context 'With a missing service'{
        It 'Throws error if the service is null' {
            Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Start-Sleep -ModuleName $moduleName
            Mock -Verifiable -ModuleName $moduleName Get-WmiObject { return $null }

            { Start-FilebeatService -FullLogPath 'logpath' } | Should -Throw
        }
    }
    Context 'With an existing service' {
        Mock -ModuleName $moduleName Get-WmiObject {
            $object =  New-Object psobject -Property @{
                MockedValue = $true
            }
            Add-Member -InputObject $object -MemberType ScriptMethod -Name StartService -Value { 
                return $this.MockecValue 
            } 
            return $object
        }
        It 'Throws error if the service is not running after start attempt' {
            Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Start-Sleep -ModuleName $moduleName
            Mock -Verifiable -ModuleName $moduleName Confirm-FilebeatServiceRunning { return $false }

            { Start-FilebeatService -FullLogPath 'logpath' } | Should -Throw
        }
        It 'Does not throw error if service starts successfully' {
            Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
            Mock -Verifiable -ModuleName $moduleName Confirm-FilebeatServiceRunning { return $true }

            { Start-FilebeatService -FullLogPath 'logpath' } | Should -Not -Throw
        }
    }

}

Describe 'Install-Filebeat logging' {

    It 'It calls Start-Log' {
        $downloadPath = "C:/fake/installpath"
        $programFileDir = "C:\Program Files\Filebeat"
        $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"

        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $correctVersion = "7.2.0"
        
        Mock -Verifiable -CommandName Get-FilebeatService -ModuleName $moduleName -MockWith { return $true } 

        Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Stop-FilebeatService -ModuleName $moduleName
        Mock -Verifiable -CommandName Get-FilebeatConfig -ModuleName $moduleName
        Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ModuleName $moduleName { return $true }

        Install-Filebeat -LogPath $logPath -LogName $logName -DownloadPath $DownloadPath -FilebeatVersion $correctVersion -HumioIngestToken 'token'
        Assert-MockCalled Start-Log -Exactly 1 {$LogPath -eq $logPath -and $LogName -eq $logName} -ModuleName $moduleName
    }
}

Describe 'Install-Filebeat setup' {
    It 'Stops filebeat service if it exists' {
        $downloadPath = "C:\fake\installpath"
        $programFileDir = "C:\Program Files\Filebeat"
        $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"

        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $correctVersion = "7.2.0"

        Mock -Verifiable -CommandName Get-FilebeatService -ModuleName $moduleName { return $true } 
        Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Stop-FilebeatService -ModuleName $moduleName
        Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName -ParameterFilter { $Path -eq $filebeatYaml -and $PSBoundParameters['Force'] -eq $true }
        Mock -Verifiable -CommandName Get-FilebeatConfig -ModuleName $moduleName
        Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ModuleName $moduleName { return $true }

        Install-Filebeat -LogPath $logPath -LogName $logName -DownloadPath $DownloadPath -FilebeatVersion $correctVersion -HumioIngestToken 'token'
        Assert-MockCalled Stop-FilebeatService -Exactly 1 -ModuleName $moduleName
    }

    It 'Calls Remove-OldFilebeatFolders, calls Install-Filebeat' { 
        $downloadPath = "C:/fake/installpath"
        $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"
        $logPath = "C:/fake/logpath"
        $logName = "fake-filebeat.log"
        $correctVersion = "7.2.0"
        $programFileDir = "C:\Program Files\Filebeat"
        $unzippedFile = "C:\Program Files\filebeat-$correctVersion-windows-x86"

        Mock -Verifiable -CommandName Get-FilebeatService -ModuleName $moduleName { return $false } 
        Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
        Mock -Verifiable -CommandName cd -ModuleName $moduleName
        Mock -Verifiable -CommandName Get-FilebeatZip -ModuleName $moduleName
        Mock -Verifiable -CommandName Install-CustomFilebeat -ModuleName $moduleName
        Mock -Verifiable -CommandName Get-FilebeatConfig -ModuleName $moduleName
        Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ModuleName $moduleName { return $true }

        Mock -Verifiable -CommandName Remove-OldFilebeatFolders -ModuleName $moduleName -MockWith { return $false }

        Install-Filebeat -LogPath $logPath -LogName $logName -DownloadPath $DownloadPath -FilebeatVersion $correctVersion -HumioIngestToken 'token'
        Assert-MockCalled Remove-OldFilebeatFolders -Exactly 1 { $FullLogPath -eq (Join-Path -Path $logPath -ChildPath $logName) -and $FilebeatVersion -eq $correctVersion } -ModuleName $moduleName
        Assert-MockCalled Get-FilebeatZip -Exactly 1 { $FullLogPath -eq (Join-Path -Path $logPath -ChildPath $logName) } -ModuleName $moduleName
    }
}

Describe 'Confirm Filebeats service is running' {
    Context 'Filbeat service not running' {
        It 'Runs start-filebeatservice if service is not started' {
            $downloadPath = "C:\fake\installpath"
            $programFileDir = "C:\Program Files\Filebeat"
            $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"
            $logPath = "C:/fake/logpath"
            $logName = "fake-filebeat.log"
            $correctVersion = "7.2.0"

            Mock -Verifiable -CommandName Get-FilebeatService -ModuleName $moduleName { return $true } 
            Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Stop-FilebeatService -ModuleName $moduleName
            Mock -Verifiable -CommandName Get-FilebeatConfig -ModuleName $moduleName

            Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ModuleName $moduleName { return $false }
            Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ParameterFilter { $PSBoundParameters['ErrorAction'] -eq "Stop" } -ModuleName $moduleName { return $true }
            Mock -Verifiable -CommandName Start-FilebeatService -ModuleName $moduleName

            Install-Filebeat -LogPath $logPath -LogName $logName -DownloadPath $DownloadPath -FilebeatVersion $correctVersion -HumioIngestToken 'token'
            Assert-MockCalled Start-FilebeatService -Exactly 1 -ModuleName $moduleName
        }
        It 'Throws error if filebeat service still not started after trying to start' {
            $downloadPath = "C:\fake\installpath"
            $programFileDir = "C:\Program Files\Filebeat"
            $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"
            $logPath = "C:/fake/logpath"
            $logName = "fake-filebeat.log"
            $correctVersion = "7.2.0"

            Mock -Verifiable -CommandName Get-FilebeatService -ModuleName $moduleName { return $true } 
            Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Stop-FilebeatService -ModuleName $moduleName
            Mock -Verifiable -CommandName Get-FilebeatConfig -ModuleName $moduleName

            Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ModuleName $moduleName { return $false }
            Mock -Verifiable -CommandName Start-FilebeatService -ModuleName $moduleName { Throw 'Service not running' }

            { Install-Filebeat -LogPath $logPath -LogName $logName -DownloadPath $DownloadPath -FilebeatVersion $correctVersion -HumioIngestToken 'token' } | Should -Throw
        }
    }
    Context 'Filebeat service is running' {
        It 'Does not run start-filebeatservice if service is not started' {
            $downloadPath = "C:\fake\installpath"
            $programFileDir = "C:\Program Files\Filebeat"
            $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"
            $logPath = "C:/fake/logpath"
            $logName = "fake-filebeat.log"
            $correctVersion = "7.2.0"

            Mock -Verifiable -CommandName Get-FilebeatService -ModuleName $moduleName { return $true }
            Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
            Mock -Verifiable -CommandName Stop-FilebeatService -ModuleName $moduleName
            Mock -Verifiable -CommandName Get-FilebeatConfig -ModuleName $moduleName

            Mock -Verifiable -CommandName Confirm-FilebeatServiceRunning -ModuleName $moduleName { return $true }
            Mock -Verifiable -CommandName Start-FilebeatService -ModuleName $moduleName

            Install-Filebeat -LogPath $logPath -LogName $logName -DownloadPath $DownloadPath -FilebeatVersion $correctVersion -HumioIngestToken 'token'
            Assert-MockCalled Start-FilebeatService -Exactly 0 -ModuleName $moduleName
        }
    }
}

Describe 'Send-HumioEvent' {
    Context 'Event is sent successfully' {
        It 'Returns True without error' {
            $source = 'tests'
            $event = 'successful-event'
            $success = $true

            Send-HumioEvent -Token $humioToken `
                -Environment 'dev' `
                -Source $source `
                -Event $event `
                -Success $success | Should Be $true 
        }

        It 'Returns True when sending with error' {
            $source = 'tests'
            $event = 'failed-event'
            $success = $false
            $encounteredError = 'Something terrible!'

            Send-HumioEvent -Token $humioToken `
                -Environment 'dev' `
                -Source $source `
                -Event $event `
                -Success $success `
                -EncounteredError $encounteredError | Should Be $true 
        }

        It 'Returns True when sending successful event with attributes' {
            $source = 'tests'
            $event = 'successful-event'
            $success = $true
            $extraAttributes = @{
                red = "fish";
                blue = "fish"
            }

            Send-HumioEvent -Token $humioToken `
                -Environment 'dev' `
                -Source $source `
                -Event $event `
                -Success $success `
                -ExtraAttributes $extraAttributes | Should Be $true 
        }

        It 'Returns True when sending failed event with attributes' {
            $source = 'tests'
            $event = 'failed-event'
            $success = $false
            $encounteredError = 'The reactor core is melted!'
            $extraAttributes = @{
                disaster = "Chernobyl"
            }

            Send-HumioEvent -Token $humioToken `
                -Environment 'dev' `
                -Source $source `
                -Event $event `
                -Success $success `
                -ExtraAttributes $extraAttributes | Should Be $true 
        }
    }    
    Context 'Event send fails' {
        It 'Returns False' {
            $fakeToken = 'blah'
            $source = 'tests'
            $event = 'failure-event'
            $success = $false

            Send-HumioEvent -Token $fakeToken `
                -Environment 'dev' `
                -Source $source `
                -Event $event `
                -Success $success | Should Be $false 
        }
    }    
}

Describe 'Merge-HashTables' {
    Context 'Two unique hashtables' {
        It 'Includes all unique key-values' {
            $hashA = @{ hello = "world" }
            $hashB = @{ hej = "verden" }

            $expectedHash = @{
                hello = "world";
                hej = "verden"
            }

            $mergedHash = Merge-HashTables -hashOne $hashA -hashTwo $hashB
            $expectedHash, $mergedHash | Test-Equality | Should -BeTrue
        }
    }
}

Describe 'Get-SendSmsBlob' {
    $accountName = "StorageAccountName"
    $accountKey = "VerySecret"
    $accountContainer = "StorageAccountContainer"
    $fakePath = "C:/temp"

    $sendSmsDirectory = "PR_SMS_UDSENDELSE"
    $sendSmsCDrive = "C:/$sendSmsDirectory"
    $sendSmsZip = "$sendSmsDirectory.zip"

    Mock -Verifiable -CommandName Join-Path { return "C:/temp" } -ModuleName $moduleName

    Mock -Verifiable -CommandName Start-Log -ModuleName $moduleName
    Mock -Verifiable -CommandName Write-Log -ModuleName $moduleName
    Mock -Verifiable -CommandName New-Item -ModuleName $moduleName
    Mock -Verifiable -CommandName Get-Blob -ModuleName $moduleName
    Mock -Verifiable -CommandName Expand-Archive -ModuleName $moduleName
    Mock -Verifiable -CommandName Remove-Item -ModuleName $moduleName

    Context 'No previous installation of SendSms exists' {

        Mock -Verifiable -CommandName Test-Path { return $false } `
            -ParameterFilter {$Path -eq $sendSmsCDrive} `
            -ModuleName $moduleName
        
        Mock -Verifiable -CommandName Test-Path { return $true } `
            -ParameterFilter {$Path -eq $sendSmsCDrive -and $PSBoundParameters['IsValid'] -eq $true} `
            -ModuleName $moduleName

        It 'Calls Get-Blob with correct params' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer 
            
            Assert-MockCalled Get-Blob -Exactly 1 `
               {$FullLogPath -eq $fakePath `
                -and $StorageAccountKey -eq $accountKey `
                -and $StorageAccountName -eq $accountName `
                -and $StorageAccountContainer -eq $accountContainer `
                -and $BlobFile -eq $sendSmsZip `
                -and $Outpath -eq $fakePath} `
               -ModuleName $moduleName            
        }

        It 'Calls Expand-Archive' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer 

            Assert-MockCalled Expand-Archive `
                -ParameterFilter {$Path -eq "$fakePath/$sendSmsZip" -and $DestinationPath -eq "C:/" -and $PSBoundParameters['Force'] -eq $true } `
                -ModuleName $moduleName 

        }

        It 'Calls Remove-Item' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer 

            Assert-MockCalled Remove-Item `
                -ParameterFilter {$Path -eq $fakePath -and $PSBoundParameters['Force'] -eq $true -and $PSBoundParameters['Recurse'] -eq $true} `
                -ModuleName $moduleName 
        }

        It 'Calls returns true' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer | Should -BeTrue
        }
    }

    Context 'Exception thrown when downloading blob' {
        
        Mock -Verifiable -CommandName Test-Path { return $false } `
            -ParameterFilter {$Path -eq $sendSmsCDrive} `
            -ModuleName $moduleName

        It 'Throws an error when Get-Blob throws' {
            Mock -Verifiable -CommandName Get-Blob { Throw 'Big problem'} -ModuleName $moduleName

            { Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer } | Should Throw
        }

        It 'Throws an error when Expand-Archive throws' {
            Mock -Verifiable -CommandName Expand-Archive { Throw 'Big problem'} -ModuleName $moduleName

            { Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer } | Should Throw
        }
    }

    Context 'Previous SendSms file existed' {

        Mock -Verifiable -CommandName Test-Path { return $true } `
            -ParameterFilter {$Path -eq $sendSmsCDrive} `
            -ModuleName $moduleName

        Mock -Verifiable -CommandName Test-Path { return $false } `
            -ParameterFilter {$Path -eq $sendSmsCDrive -and $PSBoundParameters['IsValid'] -eq $true} `
            -ModuleName $moduleName

        It 'Does not call Get-Blob' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer 

            Assert-MockCalled Get-Blob -Exactly 0 -ModuleName $moduleName
        }

        It 'Removes temp directory' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer 

            Assert-MockCalled Remove-Item `
                -ParameterFilter {$Path -eq $fakePath -and $PSBoundParameters['Force'] -eq $true -and $PSBoundParameters['Recurse'] -eq $true} `
                -ModuleName $moduleName 
        }

        It 'Returns false' {

            Get-SendSmsBlob -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -StorageAccountContainer $accountContainer | Should -BeFalse
        }
    }
}

Describe 'Invoke-AzureRmVmScript' {
    Mock -CommandName Get-AzureRmVM { [PSCustomObject]@{Location = "blah" } } -ModuleName $moduleName
    Mock -Verifiable -CommandName Remove-AzureRmVMCustomScriptExtension -ModuleName $moduleName
    Mock -Verifiable -CommandName Get-AzureRmStorageAccountKey -ModuleName $moduleName
    Mock -Verifiable -CommandName New-AzureStorageContext -ModuleName $moduleName
    Mock -Verifiable -CommandName Start-Sleep -ModuleName $moduleName
    Mock -Verifiable -CommandName Get-AzureStorageBlob -ModuleName $moduleName
    Mock -Verifiable -CommandName Set-AzureStorageBlobContent { [PSCustomObject]@{Name = "Get-Something.ps1" } } -ModuleName $moduleName

    Context 'Happy path' {
        It 'Returns true on success' {

            Mock -Verifiable -CommandName Set-AzureRmVMCustomScriptExtension { [PSCustomObject]@{StatusCode = "OK" } } -ModuleName $moduleName
            
            $resourceGroup = "azure-rg"
            $vmName = "MyVm"
            $accountName = "storageaccount"
            $accountKey = "secretkey"
            $scriptName = "Get-Something.ps1"
            $scriptBlock = { Write-Host "Hello world" }
            $extensionName = "Get-Something"

            Invoke-AzureRmVmScript -ScriptFilename $scriptName `
                -ResourceGroupName $resourceGroup `
                -VMName $vmName `
                -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -ScriptBlock $scriptBlock `
                -ExtensionName $extensionName | Should -BeTrue
        }
    }
    Context 'Sad path' {
        It 'Returns false on failure' {

            Mock -Verifiable -CommandName Set-AzureRmVMCustomScriptExtension { [PSCustomObject]@{StatusCode = "Terrible!" } } -ModuleName $moduleName
            
            $resourceGroup = "azure-rg"
            $vmName = "MyVm"
            $accountName = "storageaccount"
            $accountKey = "secretkey"
            $scriptName = "Get-Something.ps1"
            $scriptBlock = { Write-Host "Hello world" }
            $extensionName = "Get-Something"

            Invoke-AzureRmVmScript -ScriptFilename $scriptName `
                -ResourceGroupName $resourceGroup `
                -VMName $vmName `
                -StorageAccountName $accountName `
                -StorageAccountKey $accountKey `
                -ScriptBlock $scriptBlock `
                -ExtensionName $extensionName | Should -BeFalse
        }
    }
}