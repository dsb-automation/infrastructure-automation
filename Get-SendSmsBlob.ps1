[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [string] $StorageAccountName,
    
    [Parameter(Mandatory = $true)]
    [string] $StorageAccountKey,

    [Parameter(Mandatory = $true)]
    [string] $StorageAccountContainer
)

$ErrorActionPreference = "SilentlyContinue"
#Script Version
$ScriptVersion = "1.0"
#Debug mode; $true - enabled ; $false - disabled
$Debug = $true
#Log File Info
$LogPath = "C:\ProgramData\AutomationAzureOrchestration"
$LogName = "Retrieve-SendSms-$(Get-Date -f "yyyyMMddhhmmssfff").log"
$LogFile = Join-Path -Path $LogPath -ChildPath $LogName
#Temp location

$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

$tempDirectory = (Join-Path $ENV:TEMP "SendSms-$(Get-Date -f "yyyyMMddhhmmssfff")")
New-Item -ItemType Directory -Path $tempDirectory | Out-Null

$p = [Environment]::GetEnvironmentVariable("PSModulePath")
$p += ";$powershellModuleDir\"
[Environment]::SetEnvironmentVariable("PSModulePath", $p)

$sendSmsDirectory = "PR_SMS_UDSENDELSE"
$sendSmsCDrive = "C:/$sendSmsDirectory"
$sendSmsZip = "$sendSmsDirectory.zip"

Start-Log -LogPath $LogPath -LogName $Logname -ErrorAction Stop

$securityConfig = [Net.ServicePointManager]::SecurityProtocol
Write-Host "Current security protocol is: $securityConfig"
Write-Log -LogPath $LogFile -Message "Current security protocol is: $securityConfig" -Severity "Info"

Write-Host "Temp file location is: $tempDirectory"
Write-Log -LogPath $LogFile -Message "Temp file location is: $tempDirectory" -Severity "Info"

Write-Host "Storage container is: $StorageAccountContainer"
Write-Log -LogPath $LogFile -Message "Storage container is: $StorageAccountContainer" -Severity "Info"

Write-Host "Storage account name is: $StorageAccountName"
Write-Log -LogPath $LogFile -Message "Storage account name is: $StorageAccountName" -Severity "Info"

Write-Host "Storage account key is $StorageAccountKey"
Write-Log -LogPath $LogFile -Message "Storage account key is $StorageAccountKey" -Severity "Info"

Write-Host "Checking if $sendSmsDirectory exists"
Write-Log -LogPath $LogFile -Message "Checking if $sendSmsDirectory exists" -Severity "Info"

If (!(Test-Path -Path $sendSmsCDrive)) {

    Write-Host "No $sendSmsDirectory existed, downloading it now"
    Write-Log -LogPath $LogFile -Message "No $sendSmsDirectory existed, downloading it now" -Severity "Info"

    Try {
        Get-Blob -FullLogPath $LogFile `
            -StorageAccountKey $StorageAccountKey `
            -StorageAccountName $StorageAccountName `
            -StorageAccountContainer $StorageAccountContainer `
            -BlobFile $sendSmsZip `
            -OutPath $tempDirectory

        Write-Host "Expanding $tempDirectory/$sendSmsZip to C drive"
        Write-Log -LogPath $LogFile -Message "Expanding $tempDirectory/$sendSmsZip to C drive" -Severity "Info"
        Expand-Archive -Path "$tempDirectory/$sendSmsZip" -DestinationPath "C:/" -Force

        Write-Host "Removing temp directory $tempDirectory"
        Write-Log -LogPath $LogFile -Message "Removing temp directory $tempDirectory" -Severity "Info"
        Remove-Item $tempDirectory -Recurse -Force | Out-Null
    }
    Catch {
        Write-Log -LogPath $LogFile -Message "There was an error retrieving SendSMS: $_.Exception.Message" -Severity "Error"
        Write-Host "There was an error retrieving SendSMS: $_.Exception.Message"
        Throw "There was an error retrieving SendSMS: $_.Exception.Message"
    }
} Else {
    Write-Host "$sendSmsDirectory existed, exiting now"
    Write-Log -LogPath $LogFile -Message "$sendSmsDirectory existed, exiting now" -Severity "Info"
}