[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
                                        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@

function Start-Log {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [string]$LogName
    )

    If (-Not (Test-Path -Path $LogPath)) {
        Write-Host "There was no directory at $LogPath, trying to create it now"
        Try {
            New-Item -ItemType Directory -Path $LogPath -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Host "There was an error creating $LogPath"
            Throw "There was an error creating {$LogPath}: $_.Exception"
        }
    }
    Else {
        Write-Host "A directory existed at $LogPath, not trying to create one"
    }

    $logFullPath = Join-Path -Path $LogPath -ChildPath $LogName
    If(-Not (Test-Path -Path $logFullPath)){
        Write-Host "There was no logfile at $logFullPath, trying to create it now"
        Try {
            New-Item -Path $LogPath -Name $LogName -ItemType File -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Host "There was an error creating $logFullPath"
            Throw "There was an error creating {$logFullPath}: $_.Exception"
        }
    }

    If(-Not (Test-Path -Path $logFullPath -Verbose)){
        Throw "The log file should have been created but could not be found: $logFullPath"
    }
}

function Write-Log
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [string]$Environment = "dev",
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Info", "Warn","Error")]
        [string]$Severity = "Info"
    )

    Try {

        $logString = Format-LogMessage -Message $Message -Environment $Environment -LogPath $LogPath -Severity $Severity
        $logString = $logString.Trim()
        # Add-content but if error, use out-file
        Try {
            Add-Content -Path $LogPath -Value $logString -Force -ErrorAction Stop
        }
        Catch {
            Write-Host "There was an error using add-content to log file, using out-file instead"
            [string]$logString | Out-File -FilePath $LogPath -Append -Force -NoClobber
        }
    }
    Catch {
        Write-Host "There was an error writing log message: {$Message} to log: {$LogPath}: $_.Exception"
    }
}

function Format-LogMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [string]$Environment,
        
        [Parameter(Mandatory=$true)]
        [string]$Severity
    )

    $now = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    $logString = "$now $Severity message=$Message env=$Environment timeStamp=$now level=$Severity pcName=$env:computername logfile=$LogPath"
    return $logString
}

function Download-File {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FullLogPath,

        [Parameter(Mandatory=$true)]
        [string] $Url,

        [Parameter(Mandatory=$true)]
        [string] $OutPath
    )

    Write-Host "Attempting to download: $Url, to: $OutPath"
    Write-Log -LogPath $FullLogPath -Message "Attempting to download: $Url, to: $OutPath" -Severity "Info"

    $client = New-Object System.Net.WebClient
    $client.DownloadFile($Url, $OutPath)

}    

function Download-String {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FullLogPath,

        [Parameter(Mandatory=$true)]
        [string] $Url,
        
        [Parameter()]
        [string] $AuthToken
    )

    Write-Host "Attempting to download string from url: $Url"
    Write-Log -LogPath $FullLogPath -Message "Attempting to download string from url: $Url" -Severity "Info"

    $wc = New-Object System.Net.WebClient
    $machineString = $wc.DownloadString($Url)

    return $machineString
}

function Wait-ForService($servicesName, $timeLength) {
  # Get all services where DisplayName matches $serviceName and loop through each of them.
  foreach($service in (Get-Service -DisplayName "$servicesName"))
  {
      if($service.Status -eq "Stopped" ) {
        Start-Service $service.Name
      }
      # Wait for the service to reach the $serviceStatus or a maximum of specified time
      $service.WaitForStatus("Running", $timeLength)
 }

 return $service

}

function Get-FilebeatZip {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $FullLogPath,

        [Parameter(Mandatory=$true)]
        [string] $DownloadPath,

        [Parameter(Mandatory=$true)]
        [ValidateSet("7.2.0")]
        [string] $FilebeatVersion
    )

    $url = "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-$FilebeatVersion-windows-x86.zip"
    Write-Host "Attempting to download Filebeat from: $url"
    Write-Log -LogPath $FullLogPath -Message "Attempting to download from $url" -Severity "Info"
    $filebeatZipName = "filebeat.zip"
    $downloadedZip = Join-Path -Path $DownloadPath -ChildPath $filebeatZipName
    if (Test-Path -Path $downloadedZip) {
        Write-Host "Found previously downloaded filebeat at: $downloadedZip Deleting the file now"
        Write-Log -LogPath $FullLogPath -Message "Found previously downloaded filebeat at: $downloadedZip Deleting the file now" -Severity "Info"
        Remove-Item -Path $downloadedZip -Recurse
    }
    Write-Host "Attempting to download filebeat to: $downloadedZip"
    Write-Log -LogPath $FullLogPath -Message "Attempting to download filebeat to: $downloadedZip" -Severity "Info"
    
    Download-File -FullLogPath $FullLogPath -Url $url -OutPath $downloadedZip

    Write-Host "Expanding archive $downloadedZip"
    Write-Log -LogPath $FullLogPath -Message "Expanding archive $downloadedZip" -Severity "Info"
    
    $programFileDir = "C:\Program Files"
    Expand-Archive -Path $downloadedZip -DestinationPath $programFileDir -Force

    $expandedFilebeat = Join-Path -Path $programFileDir -ChildPath "filebeat-$FilebeatVersion-windows-x86"
    Rename-Item -Path $expandedFilebeat -NewName 'Filebeat' -Force -ErrorAction Stop
}

function Stop-FilebeatService {
    $service = Get-WmiObject -Class Win32_Service -Filter "name='filebeat'"
    $service.StopService()
    Start-Sleep -s 1
}

function Get-FilebeatService {
    $service = Get-Service -Name filebeat -ErrorAction SilentlyContinue
    return $service
}

function Get-FilebeatConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $FullLogPath
    )

    $filebeatYaml = "C:\Program Files\Filebeat\filebeat.yml"
    Write-Host "Removing existing filebeat config from: $filebeatYaml"
    Write-Log -LogPath $FullLogPath -Message "Removing existing filebeat config from: $filebeatYaml" -Severity "Info"
    If ((Test-Path -Path $filebeatYaml)) {
        Remove-Item -Path $filebeatYaml -Force
    }

    $configUri = "https://raw.githubusercontent.com/nkuik/dsb-automation-infrastructure/master/filebeat.yml"
    Write-Host "Attempting to download filebeat config from: $configUri"
    Write-Log -LogPath $FullLogPath -Message "Attempting to download filebeat config from: $configUri" -Severity "Info"
    
    Download-File -FullLogPath $FullLogPath -Url $configUri -OutPath $filebeatYaml
    if (-not (Test-Path -Path $filebeatYaml)) {
        Throw [System.IO.FileNotFoundException] "$filebeatYaml not found."
    }
}

function Confirm-FilebeatServiceRunning {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $FullLogPath
    )
    
    $service = Get-WmiObject -Class Win32_Service -Filter "name='filebeat'"
    $state = $service.State
    Write-Host "Filebeat service state is: $state"
    Write-Log -LogPath $FullLogPath -Message "Filebeat service state is: $state" -Severity "Info"
    if ($state -eq "Running") {
        Write-Host "Filebeat Service is running successfully"
        Write-Log -LogPath $FullLogPath -Message "Filebeat Service started successfully" -Severity "Info"
        return $true
    }
    else {
        Write-Host "Filebeat service is not running"
        Write-Log -LogPath $FullLogPath -Message "Filebeat service is not running" -Severity "Warn"
        return $false
    }
}

function Remove-OldFilebeatFolders {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $FullLogPath,

        [Parameter(Mandatory = $true)]
        [string] $FilebeatVersion
    )

    $unzippedFile = "C:\Program Files\filebeat-$FilebeatVersion-windows-x86"
    If (Test-Path -Path $unzippedFile) {
        Write-Host "Item $unzippedFile existed, removing now"
        Write-Log -LogPath $FullLogPath -Message "Item $unzippedFile existed, removing now" -Severity "Info"
        Remove-Item -Path $unzippedFile -Recurse -Force
    }
    $programFileFilebeat = "C:\Program Files\Filebeat"
    If (Test-Path -Path $programFileFilebeat) {
        Write-Host "Item $programFileFilebeat existed, removing now"
        Write-Log -LogPath $FullLogPath -Message "Item $programFileFilebeat existed, removing now" -Severity "Info"
        Remove-Item -Path $programFileFilebeat -Recurse -Force
    }
}

function Start-FilebeatService {
    [CmdletBinding()]
    param (
        [string] $FullLogPath
    )
    
    Write-Host "Trying to start Filebeat service"
    Write-Log -LogPath $FullLogPath -Message "Trying to start Filebeat service" -Severity "Info"
    $service = Get-WmiObject -Class Win32_Service -Filter "name='filebeat'"    
    If ($service -eq $null) {
        Write-Host "Filebeat service is null"
        Write-Log -LogPath $FullLogPath -Message "Filebeat service is null" -Severity "Error"
        Throw "Filebeat service is null"
        Break
    }
    $service.StartService()
    Start-Sleep -s 3
    $serviceIsRunning = Confirm-FilebeatServiceRunning -FullLogPath $FullLogPath
    If (!$serviceIsRunning) {
        Write-Host "Filebeat not running after attempting to start it"
        Write-Log -LogPath $FullLogPath -Message "Filebeat not running after attempting to start it" -Severity "Error"
        Throw "Filebeat not running after attempting to start it"
        Break
    }
}

function Install-CustomFilebeat {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $HumioIngestToken,

        [Parameter(Mandatory = $true)]
        [string] $FullLogPath,

        [Parameter(Mandatory = $true)]
        [string] $FilebeatLocation
    )

    # Delete and stop the service if it already exists.
    Write-Host "Checking for existing Filebeat service again."
    Write-Log -LogPath $FullLogPath -Message "Checking for existing Filebeat service again." -Severity "Info"

    if (Get-Service filebeat -ErrorAction SilentlyContinue) {
        Write-Host "Filebeat service existed"
        Write-Log -LogPath $FullLogPath -Message "Filebeat service existed" -Severity "Info"
        $service = Get-WmiObject -Class Win32_Service -Filter "name='filebeat'"
        $service.StopService()
        Start-Sleep -s 1
        $service.delete()
    }

    $elasticToken = "output.elasticsearch.password=$HumioIngestToken"
    Write-Host "Elastic setting is $elasticToken"
    # Create the new service.
    New-Service -name filebeat `
    -displayName Filebeat `
    -binaryPathName "`"$FilebeatLocation\filebeat.exe`" -c `"$FilebeatLocation\filebeat.yml`" -path.home `"$FilebeatLocation`" -path.data `"C:\ProgramData\filebeat`" -path.logs `"C:\ProgramData\filebeat\logs`" -E `"$elasticToken`""

    # Attempt to set the service to delayed start using sc config.
    Try {
        Start-Process -FilePath sc.exe -ArgumentList 'config filebeat start=delayed-auto'
    }
    Catch { 
        Throw "There was an exception starting filebeat process: $_.Exception"
    }
}

function Install-Filebeat {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $LogPath,

        [Parameter(Mandatory = $true)]
        [string] $LogName,

        [Parameter(Mandatory=$true)]
        [string] $DownloadPath,

        [Parameter(Mandatory=$true)]
        [ValidateSet("7.2.0")]
        [string] $FilebeatVersion,

        [Parameter(Mandatory=$true)]
        [string] $HumioIngestToken
    )
    
    $beforeCd = Get-Location

    Start-Log -LogPath $LogPath -LogName $LogName
    $FullLogPath = Join-Path -Path $LogPath -ChildPath $LogName

    Write-Host "Trying to install filebeat version: $FilebeatVersion"
    Write-Log -LogPath $FullLogPath -Message "Trying to install filebeat version: $FilebeatVersion" -Severity "Info"

    $filebeatService = Get-FilebeatService
    If ($filebeatService) {
        Write-Host "Filebeat service already installed, attempting to stop service"
        Write-Log -LogPath $FullLogPath -Message "Filebeat service already installed, attempting to stop service" -Severity "Info"
        Try {
            Stop-FilebeatService -ErrorAction Stop
        }
        Catch {
            Write-Host "There was an exception stopping Filebeat service: $_.Exception"
            Write-Log -LogPath $FullLogPath -Message $_.Exception -Severity "Error"
            Break
        } 
    }
    Else {
        Write-Host "No Filebeat service existed"
        Write-Log -LogPath $FullLogPath -Message "No Filebeat service existed" -Severity "Info"
        
        Try {
            Write-Host "Removing old Filebeat folders if they exist"
            Write-Log -LogPath $FullLogPath -Message "Removing old Filebeat folders if they exist" -Severity "Info"
            Remove-OldFilebeatFolders -FullLogPath $FullLogPath -FilebeatVersion $FilebeatVersion -ErrorAction Stop
        }
        Catch {
            Write-Host "There was an exception deleting old Filebeat folders: $_.Exception"
            Write-Log -LogPath $FullLogPath -Message "There was an exception deleting old Filebeat folders: $_.Exception" -Severity "Error"
            Throw "There was an exception deleting old Filebeat folders: $_.Exception"
            Break
        }

        Try {
            Write-Host "Attempting to retrieve and unzip Filebeat zip"
            Write-Log -LogPath $FullLogPath -Message "Attempting to retrieve and unzip Filebeat zip" -Severity "Info"
            Get-FilebeatZip -FullLogPath $FullLogPath -DownloadPath $DownloadPath -FilebeatVersion $FilebeatVersion -ErrorAction Stop
        }
        Catch {
            Write-Host "There was an exception retrieving/expanding filebeat zip: $_.Exception"
            Write-Log -LogPath $FullLogPath -Message "There was an exception retrieving/expanding filebeat zip: $_.Exception" -Severity "Error"
            Throw "There was an exception retrieving/expanding filebeat zip: $_.Exception"
            Break
        }

        Write-Host "Attempting to install Filebeat"
        Write-Log -LogPath $FullLogPath -Message "Attempting to install Filebeat" -Severity "Info"

        Write-Host "Humio Token is $HumioIngestToken"
        Write-Log -LogPath $FullLogPath -Message "Humio Token is $HumioIngestToken" -Severity "Info"
        
        $filebeatLocation = 'C:\Program Files\Filebeat'
        cd $filebeatLocation
        Try {
            Write-Host "Running custom filebeat installation function"
            Write-Log -LogPath $FullLogPath -Message "Running custom filebeat installation function" -Severity "Info"
            Install-CustomFilebeat -HumioIngestToken "$HumioIngestToken" -FullLogPath $FullLogPath -FilebeatLocation $FilebeatLocation -ErrorAction Stop 
            cd $beforeCd
        }
        Catch {
            cd $beforeCd
            Write-Host "There was an exception installing Filebeat: $_.Exception"
            Write-Log -LogPath $FullLogPath -Message $_.Exception -Severity "Error"
            Throw "There was an exception installing Filebeat: $_.Exception"
            Break
        }
    }

    Write-Host "Retrieving filebeat config"
    Write-Log -LogPath $FullLogPath -Message "Retrieving filebeat config" -Severity "Info"

    Write-Host "Attempting to retrieve filebeat config"
    Write-Log -LogPath $FullLogPath -Message "Attempting to retrieve filebeat config" -Severity "Info"
    Try {
        Get-FilebeatConfig -FullLogPath $FullLogPath -ErrorAction Stop
    }
    Catch {
        Write-Host "There was an exception retrieving the filebeat config: $_.Exception"
        Write-Log -LogPath $FullLogPath -Message "There was an exception retrieving the filebeat config: $_.Exception" -Severity "Error"
        Throw "There was an exception retrieving the filebeat config: $_.Exception"
        Break
    }

    Write-Host "Attempting to start filebeat service if it's not running"
    Write-Log -LogPath $FullLogPath -Message "Attempting to start filebeat service if it's not running" -Severity "Info"

    Write-Host "Checking for running filebeat service"
    Write-Log -LogPath $FullLogPath -Message "Checking for running filebeat service" -Severity "Info"
    If (!(Confirm-FilebeatServiceRunning -FullLogPath $FullLogPath)) {
        Write-Host "Filebeats service was not running, trying to start it now"
        Write-Log -LogPath $FullLogPath -Message "Filebeats service was not running, trying to start it now" -Severity "Warn"
        Try {
            Start-FilebeatService -FullLogPath $FullLogPath -ErrorAction Stop
        }
        Catch {
            Write-Host "There was an exception trying to run the filebeat service: $_.Exception"
            Write-Log -LogPath $FullLogPath -Message "There was an exception trying to run the filebeat service: $_.Exception" -Severity "Error"
            Throw "There was an exception trying to run the filebeat service: $_.Exception"
            Break
        }
    }
    Else {
        Write-Host "Filebeats service is running, exiting script now"
        Write-Log -LogPath $FullLogPath -Message "Filebeats service is running, exiting script now" -Severity "Info"
    }

    Write-Host "Install Filebeat installed without error"
    Write-Log -LogPath $FullLogPath -Message "Install Filebeat installed without error" -Severity "Info"
}

function Get-Blob {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $BlobFile,
            
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountName,
        
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountKey,

        [Parameter(Mandatory = $true)]
        [string] $StorageAccountContainer,

        [Parameter(Mandatory = $true)]
        [string] $OutPath,

        [Parameter(Mandatory = $true)]
        [string] $FullLogPath
    )

    $wc = New-Object System.Net.WebClient

    $OutPath = Join-Path -Path $OutPath -ChildPath $BlobFile

    Write-Host "Blob to download is: $BlobFile"
    Write-Log -LogPath $FullLogPath -Message "Blob to download is: $BlobFile" -Severity "Info"

    Write-Host "Location to save blob is: $OutPath"
    Write-Log -LogPath $FullLogPath -Message "Location to save blob is: $OutPath" -Severity "Info"

    Write-Host "Storage container is: $StorageAccountContainer"
    Write-Log -LogPath $FullLogPath -Message "Storage container is: $StorageAccountContainer" -Severity "Info"

    Write-Host "Storage account name is: $StorageAccountName"
    Write-Log -LogPath $FullLogPath -Message "Storage account name is: $StorageAccountName" -Severity "Info"

    Write-Host "Storage account key is $StorageAccountKey"
    Write-Log -LogPath $FullLogPath -Message "Storage account key is $StorageAccountKey" -Severity "Info"

    $method = "GET"
    $headerDate = '2015-02-21'
    $wc.Headers.Add("x-ms-version", "$headerDate")
    $Url = "https://$StorageAccountName.blob.core.windows.net/$StorageAccountContainer/$BlobFile"

    Write-Host "Blob URL is $Url"
    Write-Log -LogPath $FullLogPath -Message "Blob URL is $Url" -Severity "Info"
    
    $xmsdate = (get-date -format r).ToString()
    $wc.Headers.Add("x-ms-date", $xmsdate)

    $signatureString = "$method$([char]10)$([char]10)$([char]10)$contentLength$([char]10)$([char]10)$([char]10)$([char]10)$([char]10)$([char]10)$([char]10)$([char]10)$([char]10)"
    #Add CanonicalizedHeaders
    $signatureString += "x-ms-date:" + $wc.Headers["x-ms-date"] + "$([char]10)"
    $signatureString += "x-ms-version:" + $wc.Headers["x-ms-version"] + "$([char]10)"
    #Add CanonicalizedResource
    $uri = New-Object System.Uri -ArgumentList $url
    $signatureString += "/" + $StorageAccountName + $uri.AbsolutePath

    $dataToMac = [System.Text.Encoding]::UTF8.GetBytes($signatureString)
    $accountKeyBytes = [System.Convert]::FromBase64String($StorageAccountKey)
    $hmac = new-object System.Security.Cryptography.HMACSHA256((, $accountKeyBytes))
    $signature = [System.Convert]::ToBase64String($hmac.ComputeHash($dataToMac))

    $wc.Headers.Add("Authorization", "SharedKey " + $StorageAccountName + ":" + $signature);

    Try {
        Write-Host "Attempting file download now"
        Write-Log -LogPath $FullLogPath -Message "Attempting file download now" -Severity "Info"

        $wc.DownloadFile($Url, $OutPath)
    }
    Catch {
        Write-Host "There was a problem retrieving the file: $_.Exception.Message"
        Write-Log -LogPath $FullLogPath -Message "There was a problem retrieving the file: $_.Exception.Message" -Severity "Error"
        Throw "There was an error retrieving blob: $_.Exception.Message"
        Break
    }

    If (!(Test-Path -Path $OutPath)) {
        Write-Host "File did not exist after attempting retrieval"
        Write-Log -LogPath $FullLogPath -Message "File did not exist after attempting retrieval" -Severity "Error"
        Throw "Blob to download did not exist"
        Break
    }
    Else {
        Write-Host "File did exist after attempting retrieval"
        Write-Log -LogPath $FullLogPath -Message "File did exist after attempting retrieval" -Severity "Info"
    }
}

function Get-SendSmsBlob {
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

    #Log File Info
    $LogPath = "C:\ProgramData\AutomationAzureOrchestration"
    $LogName = "Retrieve-SendSms-$(Get-Date -f "yyyyMMddhhmmssfff").log"
    $LogFile = Join-Path -Path $LogPath -ChildPath $LogName
    #Temp location

    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $tempDirectory = (Join-Path $ENV:TEMP "SendSms-$(Get-Date -f "yyyyMMddhhmmssfff")")
    New-Item -ItemType Directory -Path $tempDirectory | Out-Null

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

    # TODO: Return whether or not the file exists
    Remove-Item -Path $tempDirectory -Recurse -Force | Out-Null
}

function Merge-HashTables {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $hashOne,
        
        [Parameter(Mandatory = $true)]
        [hashtable] $hashTwo
    )

    $keys = $hashOne.getenumerator() | foreach-object {$_.key}
    $keys | foreach-object {
        $key = $_
        if ($hashTwo.containskey($key))
        {
            $hashOne.remove($key)
        }
    }
    $hashTwo = $hashOne + $hashTwo
    return $hashTwo
}


# TODO: Allow extra params
function Send-HumioEvent {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Token,

        [Parameter(Mandatory = $true)]
        [string] $Environment,

        [Parameter(Mandatory = $true)]
        [string] $Source,

        [Parameter(Mandatory = $true)]
        [string] $Event,

        [Parameter(Mandatory = $true)]
        [bool] $Success,

        [Parameter()]
        [string] $EncounteredError = 'null',

        [Parameter()]
        [hashtable] $ExtraAttributes = @{}

    )

    $standardAttributes = @{
        event = $Event;
        success = $Success;
        error = $EncounteredError
    }
    $combinedAttributes = Merge-HashTables -hashOne $standardAttributes -hashTwo $ExtraAttributes
    $attributesString = $combinedAttributes | ConvertTo-Json

    $timestamp = Get-Date -Format "o"
    $url = 'https://cloud.humio.com/api/v1/ingest/humio-structured'
    $headers = @{
        'Authorization' = 'Bearer ' + $Token;
        'Content-Type' = 'application/json'
    }

$structuredString = @"
[
  {
    "tags": {
      "env": "$Environment",
      "source": "$Source"
    },
    "events": [
      {
        "timestamp": "$timestamp",
        "attributes": $attributesString 
      }
    ]
  }
]
"@

    try {
        $sendEventRequest = Invoke-WebRequest -UseBasicParsing $url `
            -Method 'POST' `
            -Headers $headers `
            -Body $structuredString 
    }
    catch [System.Net.WebException] {
        return $false
    }
    return $sendEventRequest.StatusCode -eq 200
}


Export-ModuleMember -Function Start-Log
Export-ModuleMember -Function Write-Log
Export-ModuleMember -Function Wait-ForService
Export-ModuleMember -Function Download-File
Export-ModuleMember -Function Download-String
Export-ModuleMember -Function Format-LogMessage
Export-ModuleMember -Function Install-Filebeat
Export-ModuleMember -Function Get-FilebeatZip
Export-ModuleMember -Function Stop-FilebeatService
Export-ModuleMember -Function Get-FilebeatService
Export-ModuleMember -Function Get-FilebeatConfig
Export-ModuleMember -Function Start-FilebeatService
Export-ModuleMember -Function Remove-OldFilebeatFolders
Export-ModuleMember -Function Confirm-FilebeatServiceRunning
Export-ModuleMember -Function Get-Blob
Export-ModuleMember -Function Get-SendSmsBlob
Export-ModuleMember -Function Merge-HashTables
Export-ModuleMember -Function Send-HumioEvent