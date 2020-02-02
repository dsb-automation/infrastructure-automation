Param (
    [Parameter(Mandatory = $true)]
    [string] $LogPath,

    [Parameter(Mandatory = $true)]
    [string] $LogName,

    [Parameter(Mandatory = $true)]
    [string] $OrchestratorUrl,

    [Parameter(Mandatory = $true)]
    [string] $OrchestratorApiUrl,

    [Parameter(Mandatory = $true)]
    [string] $OrchestratorApiToken
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$fullLogPath = Join-Path -Path $LogPath -ChildPath $LogName
Start-Log -LogPath $LogPath -LogName $LogName

$robotExePath = [System.IO.Path]::Combine(${ENV:ProgramFiles(x86)}, "UiPath", "Studio", "UiRobot.exe")
Write-Host "Robot exe is $robotExePath"
Write-Log -LogPath $fullLogPath -Message "Robot exe is $robotExePath" -Severity 'Info'

If (-Not (Test-Path $robotExePath)) {
    Write-Log -LogPath $fullLogPath -Message "Robot exe was not found" -Severity 'Error'
    Throw "No robot exe was found on the $env:computername"
} else {
    Write-Host "Robot exe found at $robotExePath"
    Write-Log -LogPath $fullLogPath -Message "Robot exe found at $robotExePath" -Severity 'Info'
}

Write-Host "Orchestrator API Url is $OrchestratorApiUrl"
Write-Log -LogPath $fullLogPath -Message "Orchestrator API Url is $OrchestratorApiUrl" -Severity "Info"

Try {
    $machinesUrl = "$OrchestratorApiUrl/api/v1/all-machines"
    Write-Host "Url for retrieving machine keys is $machinesUrl"
    Write-Log -LogPath $fullLogPath -Message "Url for retrieving machine keys is $machinesUrl" -Severity "Info"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.add('Authorization', $OrchestratorApiToken) 
    $machineString = $wc.DownloadString($machinesUrl)
    Write-Host "Machines are $machineString"
    $machines =  $machineString | ConvertFrom-Json

    $RobotKey = $null
    ForEach ($machine in $machines) {
        If ($env:computername -eq $machine.name) {
            $RobotKey = $machine.key
        }
    }

    Write-Host "RobotKey is null: " ($RobotKey -eq $null)
    If ($RobotKey -eq $null) {
        Write-Log -LogPath $fullLogPath -Message "No license key found for machine: $env:computername" -Severity 'Info'
        Write-Host "No license key found for machine: $env:computername"
        Throw "No license key found for machine: $env:computername"
        Break
    }

    Write-Log -LogPath $fullLogPath -Message "License key for $env:computername is: $RobotKey" -Severity 'Info'
    Write-Host "License key for $env:computername is: $RobotKey"
    Write-Log -LogPath $fullLogPath -Message "Orchestrator URL to connect to is: $OrchestratorUrl" -Severity 'Info'
    Write-Host "Orchestrator URL to connect to is: $OrchestratorUrl"

    $service = Get-Service -DisplayName 'UiPath Robot*'
    If ($service.Status -eq "Running") {
        Write-Log -LogPath $fullLogPath -Message "Robot service was running." -Severity 'Info'
        Write-Host "Robot service was running."
    } Else {
        Write-Log -LogPath $fullLogPath -Message "Robot service was not running, starting it now." -Severity 'Info'
        Write-Host "Robot service was not running, starting it now."
        Start-Process -FilePath $robotExePath -Wait -Verb runAs -WindowStyle Hidden
        $waitForRobotSVC = Wait-ForService "UiPath Robot*" "00:01:20"
    }

    # if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
    Write-Log -LogPath $fullLogPath -Message "Running robot.exe connection command" -Severity 'Info'
    Write-Host "Running robot.exe connection command"
    $cmdArgList = @(
        "--connect",
        "-url", "$OrchestratorUrl",
        "-key", "$RobotKey"
    )
    Try  {
        Write-Log -LogPath $fullLogPath -Message "Attempting robot connect command" -Severity 'Info'
        Write-Host "Attempting robot connect command"
        $connectOutput = cmd /c $robotExePath $cmdArgList '2>&1'
        Write-Host "Connect robot output is: $connectOutput"
        Write-Log -LogPath $fullLogPath -Message "Connect robot output is: $connectOutput" -Severity 'Info'
    }
    Catch {
        if ($_.Exception) {
            Write-Host "There was an error connecting the machine to $OrchestratorUrl, exception: $_.Exception"
            Write-Log -LogPath $fullLogPath -Message $_.Exception -Severity 'Error'
            Throw "There was an error connecting the machine to $OrchestratorUrl, exception: $_.Exception"
        }
        else {
            Write-Host "There was an error connecting the machine to $OrchestratorUrl, but the exception was empty"
            Write-Log -LogPath $fullLogPath -Message "There was an error, but it was blank" -Severity 'Error'
            Throw "There was an error connecting the machine to $OrchestratorUrl, but the exception was empty"
        }
        Break   
    }
    If (-Not (($connectOutput -eq $null) -Or ($connectOutput -like "*Orchestrator already connected!*"))) {
        Write-Log -LogPath $fullLogPath -Message "The robot was not connected correctly: $connectOutput" -Severity 'Info'
        Throw $connectOutput
    }
}
Catch {
    if ($_.Exception) {
        Write-Host "There was an error connecting the machine to $machinesUrl, exception: $_.Exception"
        Write-Log -LogPath $fullLogPath -Message $_.Exception -Severity 'Error'
        Throw "There was an error connecting the machine to $orchMachines, exception: $_.Exception"
    }
    else {
        Write-Host "There was an error connecting the machine to $orchMachines, but the exception was empty"
        Write-Log -LogPath $fullLogPath -Message "There was an error, but it was blank" -Severity 'Error'
        Throw "There was an error connecting the machine to $orchMachines, but the exception was empty"
    }
    Break
}

Write-Log -LogPath $fullLogPath -Message "Robot was connected correctly" -Severity "Info"
Write-Host "Robot was connected correctly"
