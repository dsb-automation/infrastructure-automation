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
        Get-FileLockProcess -FilePath $LogPath

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


<#
.SYNOPSIS
    Check which process is locking a file
.DESCRIPTION
    On Windows, Get-FileLockProcess takes a path to a file and returns a System.Collections.Generic.List of
    System.Diagnostic.Process objects (one or more processes could have a lock on a specific file, which is why
    a List is used).
    On Linux, this function returns a PSCustomObject with similar properties.
.NOTES
    Windows solution credit to: https://stackoverflow.com/a/20623311
.PARAMETER FilePath
    This parameter is MANDATORY.
    This parameter takes a string that represents a full path to a file.
    
.EXAMPLE
    # On Windows...
    PS C:\Users\testadmin> Get-FileLockProcess -FilePath "$HOME\Downloads\call_activity_2017_Nov.xlsx"
        
    Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
    -------  ------    -----      -----     ------     --  -- -----------
    1074      51    50056      86984       5.86   2856   2 EXCEL
.EXAMPLE
    # On Linux/MacOS
    PS /home/pdadmin/Downloads> Get-FileLockProcess -FilePath "/home/pdadmin/Downloads/test.txt"
    
    COMMAND  : bash
    PID      : 244585
    USER     : pdadmin
    FD       : 3w
    TYPE     : REG
    DEVICE   : 253,2
    SIZE/OFF : 0
    NODE     : 100798534
    NAME     : /home/pdadmin/Downloads/test.txt
#>

function Get-FileLockProcess {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$FilePath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (! $(Test-Path $FilePath)) {
        Write-Error "The path $FilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
        $($PSVersionTable.PSVersion.Major -le 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
        $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    
        $AssembliesFullInfo = $CurrentlyLoadedAssemblies | Where-Object {
            $_.GetName().Name -eq "Microsoft.CSharp" -or
            $_.GetName().Name -eq "mscorlib" -or
            $_.GetName().Name -eq "System" -or
            $_.GetName().Name -eq "System.Collections" -or
            $_.GetName().Name -eq "System.Core" -or
            $_.GetName().Name -eq "System.IO" -or
            $_.GetName().Name -eq "System.Linq" -or
            $_.GetName().Name -eq "System.Runtime" -or
            $_.GetName().Name -eq "System.Runtime.Extensions" -or
            $_.GetName().Name -eq "System.Runtime.InteropServices"
        }
        $AssembliesFullInfo = $AssembliesFullInfo | Where-Object { $_.IsDynamic -eq $False }
  
        $ReferencedAssemblies = $AssembliesFullInfo.FullName | Sort-Object | Get-Unique

        $usingStatementsAsString = @"
        using Microsoft.CSharp;
        using System.Collections.Generic;
        using System.Collections;
        using System.IO;
        using System.Linq;
        using System.Runtime.InteropServices;
        using System.Runtime;
        using System;
        using System.Diagnostics;
"@
        
        $TypeDefinition = @"
        $usingStatementsAsString
        
        namespace MyCore.Utils
        {
            static public class FileLockUtil
            {
                [StructLayout(LayoutKind.Sequential)]
                struct RM_UNIQUE_PROCESS
                {
                    public int dwProcessId;
                    public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
                }
        
                const int RmRebootReasonNone = 0;
                const int CCH_RM_MAX_APP_NAME = 255;
                const int CCH_RM_MAX_SVC_NAME = 63;
        
                enum RM_APP_TYPE
                {
                    RmUnknownApp = 0,
                    RmMainWindow = 1,
                    RmOtherWindow = 2,
                    RmService = 3,
                    RmExplorer = 4,
                    RmConsole = 5,
                    RmCritical = 1000
                }
        
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                struct RM_PROCESS_INFO
                {
                    public RM_UNIQUE_PROCESS Process;
        
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
                    public string strAppName;
        
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
                    public string strServiceShortName;
        
                    public RM_APP_TYPE ApplicationType;
                    public uint AppStatus;
                    public uint TSSessionId;
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool bRestartable;
                }
        
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                static extern int RmRegisterResources(uint pSessionHandle,
                                                    UInt32 nFiles,
                                                    string[] rgsFilenames,
                                                    UInt32 nApplications,
                                                    [In] RM_UNIQUE_PROCESS[] rgApplications,
                                                    UInt32 nServices,
                                                    string[] rgsServiceNames);
        
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
                static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
        
                [DllImport("rstrtmgr.dll")]
                static extern int RmEndSession(uint pSessionHandle);
        
                [DllImport("rstrtmgr.dll")]
                static extern int RmGetList(uint dwSessionHandle,
                                            out uint pnProcInfoNeeded,
                                            ref uint pnProcInfo,
                                            [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
                                            ref uint lpdwRebootReasons);
        
                /// <summary>
                /// Find out what process(es) have a lock on the specified file.
                /// </summary>
                /// <param name="path">Path of the file.</param>
                /// <returns>Processes locking the file</returns>
                /// <remarks>See also:
                /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa373661(v=vs.85).aspx
                /// http://wyupdate.googlecode.com/svn-history/r401/trunk/frmFilesInUse.cs (no copyright in code at time of viewing)
                /// 
                /// </remarks>
                static public List<Process> WhoIsLocking(string path)
                {
                    uint handle;
                    string key = Guid.NewGuid().ToString();
                    List<Process> processes = new List<Process>();
        
                    int res = RmStartSession(out handle, 0, key);
                    if (res != 0) throw new Exception("Could not begin restart session.  Unable to determine file locker.");
        
                    try
                    {
                        const int ERROR_MORE_DATA = 234;
                        uint pnProcInfoNeeded = 0,
                            pnProcInfo = 0,
                            lpdwRebootReasons = RmRebootReasonNone;
        
                        string[] resources = new string[] { path }; // Just checking on one resource.
        
                        res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);
        
                        if (res != 0) throw new Exception("Could not register resource.");                                    
        
                        //Note: there's a race condition here -- the first call to RmGetList() returns
                        //      the total number of process. However, when we call RmGetList() again to get
                        //      the actual processes this number may have increased.
                        res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
        
                        if (res == ERROR_MORE_DATA)
                        {
                            // Create an array to store the process results
                            RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;
        
                            // Get the list
                            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                            if (res == 0)
                            {
                                processes = new List<Process>((int)pnProcInfo);
        
                                // Enumerate all of the results and add them to the 
                                // list to be returned
                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    try
                                    {
                                        processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                                    }
                                    // catch the error -- in case the process is no longer running
                                    catch (ArgumentException) { }
                                }
                            }
                            else throw new Exception("Could not list processes locking resource.");                    
                        }
                        else if (res != 0) throw new Exception("Could not list processes locking resource. Failed to get size of result.");                    
                    }
                    finally
                    {
                        RmEndSession(handle);
                    }
        
                    return processes;
                }
            }
        }
"@

        $CheckMyCoreUtilsFileLockUtilLoaded = $CurrentlyLoadedAssemblies | Where-Object { $_.ExportedTypes -like "MyCore.Utils.FileLockUtil*" }
        if ($CheckMyCoreUtilsFileLockUtilLoaded -eq $null) {
            Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
        }
        else {
            Write-Verbose "The Namespace MyCore.Utils Class FileLockUtil is already loaded and available!"
        }

        $Result = [MyCore.Utils.FileLockUtil]::WhoIsLocking($FilePath)
    }
    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
        $lsofOutput = lsof $FilePath

        function Parse-lsofStrings ($lsofOutput, $Index) {
            $($lsofOutput[$Index] -split " " | foreach {
                    if (![String]::IsNullOrWhiteSpace($_)) {
                        $_
                    }
                }).Trim()
        }

        $lsofOutputHeaders = Parse-lsofStrings -lsofOutput $lsofOutput -Index 0
        $lsofOutputValues = Parse-lsofStrings -lsofOutput $lsofOutput -Index 1

        $Result = [pscustomobject]@{ }
        for ($i = 0; $i -lt $lsofOutputHeaders.Count; $i++) {
            $Result | Add-Member -MemberType NoteProperty -Name $lsofOutputHeaders[$i] -Value $lsofOutputValues[$i]
        }
    }

    $Result
    
    ##### END Main Body #####

}