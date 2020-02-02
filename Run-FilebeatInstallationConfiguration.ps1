[CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $FilebeatVersion,

        [Parameter(Mandatory = $true)]
        [string] $HumioIngestToken
    )

$script:ErrorActionPreference = "SilentlyContinue"
$script:sScriptVersion = "1.0"
#Debug mode; $true - enabled ; $false - disabled
$script:sDebug = $true
#Log File Info
$script:sLogPath = "C:\ProgramData\AutomationAzureOrchestration"
$script:installFilebeatLog = "Install-Filebeat-$(Get-Date -f "yyyyMMddhhmmssfff").log"
$script:LogFile = Join-Path -Path $sLogPath -ChildPath $installFilebeatLog
# Orchestration script directory
$script:orchModuleDir = "C:\Program Files\WindowsPowerShell\Modules\Dsb.RobotOrchestration"
#Orchestrator SSL check
$sslCheck = $false

function Main {
    Begin {
        #Define TLS for Invoke-WebRequest
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if(!$sslCheck) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }

        If (-Not (Test-Path $orchModuleDir)) {
            Write-Host "Creating program file dir at: $orchModuleDir"
            New-Item -ItemType Directory -Path $orchModuleDir
        }

        # Change to invoke-webrequest
        $wc = New-Object System.Net.WebClient
        $orchModule = "https://raw.githubusercontent.com/nkuik/dsb-automation-infrastructure/master/Dsb.RobotOrchestration.psm1"
        Write-Host "Attempting to download file from from: $orchModule"
        $orchModuleDownload = "$orchModuleDir\Dsb.RobotOrchestration.psm1"
        $wc.DownloadFile($orchModule, $orchModuleDownload)     

        $p = [Environment]::GetEnvironmentVariable("PSModulePath")
        $p += ";C:\Program Files\WindowsPowerShell\Modules\"
        [Environment]::SetEnvironmentVariable("PSModulePath", $p)
        
        Import-Module Dsb.RobotOrchestration
    }   

    Process {
        Try {
            Install-Filebeat -LogPath $sLogPath -LogName $installFilebeatScript -InstallationPath $script:tempDirectory -FilebeatVersion 7.2.0
        }
        Catch {
            Write-Host "There was an error trying to install Filebeats, exception: $_.Exception"
            Write-Log -LogPath $LogFile -Message $_.Exception -Severity "Error"
            Throw 'There was a problem installing Filebeats'
        }

        End {
            Write-Host "$MyInvocation.MyCommand.Name finished without throwing error"
            Write-Log -LogPath $LogFile -Message "$MyInvocation.MyCommand.Name finished without throwing error" -Severity "Info"
            Write-Host "$MyInvocation.MyCommand.Name is exiting"
            Write-Log -LogPath $LogFile -Message "$MyInvocation.MyCommand.Name is exiting" -Severity "Info"        
        }
    }
}

Main