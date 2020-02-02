[CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("18.4.5","19.4.1","19.4.2","19.4.3","19.10.1")]
        [string] $studioVersion,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Unattended","Attended","Development","Nonproduction")]
        [string] $robotType,

        [Parameter()]
        [String] $orchestratorUrl,

        [Parameter()]
        [String] $machineKeysUrl,

        [Parameter()]
        [String] $tenant,

        [Parameter()]
        [string] $installationFolder,

        [Parameter()]
        [string] $hostingType
    )
#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"
#Script Version
$sScriptVersion = "1.0"
#Debug mode; $true - enabled ; $false - disabled
$sDebug = $true
#Log File Info
$sLogPath = "C:\ProgramData\AutomationAzureOrchestration"
$sLogName = "Install-UiPath-$(Get-Date -f "yyyyMMddhhmmssfff").log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName
#Orchestrator SSL check
$orchSSLcheck = $false

function Main {

  Begin{

      #Log log log
      Write-Host "Install-UiPath starts"
      Log-Write -LogPath $sLogFile -LineValue "Install-UiPath starts"

      #Define TLS for Invoke-WebRequest
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

      if(!$orchSSLcheck) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
      }

      #Setup temp dir in %appdata%\Local\Temp
      $script:tempDirectory = (Join-Path $ENV:TEMP "UiPath-$(Get-Date -f "yyyyMMddhhmmssfff")")
      New-Item -ItemType Directory -Path $script:tempDirectory | Out-Null

      #Download UiPlatform
      $msiName = 'UiPathStudio.msi'
      $msiPath = Join-Path $script:tempDirectory $msiName
      $robotExePath = Get-UiRobotExePath

      Write-Host "The result of Get-UiRobotExePath is: $robotExePath"
      if (!(Test-Path $robotExePath)) {
        Download-File -url "https://download.uipath.com/versions/$studioVersion/UiPathStudio.msi" -outputFile $msiPath
      }
  }

  Process {
    #Get Robot path
    $robotExePath = Get-UiRobotExePath

    if(!(Test-Path $robotExePath)) {

      Write-Host "Installing UiPath Robot Type [$robotType]"
      Log-Write -LogPath $sLogFile -LineValue "Installing UiPath Robot Type [$robotType]"

        #Install the Robot
        if ($robotType -eq "Development") {
                # log log log
                Write-Host "Installing UiPath Robot with Studio Feature"
                Log-Write -LogPath $sLogFile -LineValue "Installing UiPath Robot with Studio Feature"
                $msiFeatures = @("DesktopFeature","Robot","Studio","StartupLauncher","RegisterService","Packages")
        } Else {
                # log log log
                Write-Host "Installing UiPath Robot without Studio Feature"
                Log-Write -LogPath $sLogFile -LineValue "Installing UiPath Robot without Studio Feature"
                $msiFeatures = @("DesktopFeature","Robot","StartupLauncher","RegisterService","Packages")
        }

        Try {
            if ($installationFolder) {
                Write-Host "Calling Install-Robot with argument installationFolder: $installationFolder"
                Log-Write -LogPath $sLogFile -LineValue "Calling Install-Robot with argument installationFolder: $installationFolder"

                $installResult = Install-UiPath -msiPath $msiPath -installationFolder $installationFolder -msiFeatures $msiFeatures
                $uiPathDir = "$installationFolder\UiPath"
                if (!(Test-Path $uiPathDir)) {
                    throw "Could not find installation of UiPath at $installationFolder"
                }
            }
            Else {
                $installResult = Install-UiPath -msiPath $msiPath -msiFeatures $msiFeatures
            }
        }
        Catch {
            if ($_.Exception) {
              Write-Host "There was an error installing UiPath: $_.Exception"
              Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
            }
            Else {
              Write-Host "There was an error installing UiPath, but the exception was empty"
              Log-Error -LogPath $sLogFile -ErrorDesc "There was an error, but it was blank" -ExitGracefully $True
            }
            Break
        }

    } Else {
      Write-Host "Previous instance of UiRobot.exe existed at $robotExePath, not installing the robot"
      Log-Write -LogPath $sLogFile -LineValue "Previous instance of UiRobot.exe existed at $robotExePath, not installing the robot"
    }

    Write-Host "Removing temp directory $($script:tempDirectory)"
    Log-Write -LogPath $sLogFile -LineValue "Removing temp directory $($script:tempDirectory)"
    Remove-Item $script:tempDirectory -Recurse -Force | Out-Null


    Write-Host "Checking robot service now"
    Log-Write -LogPath $sLogFile -LineValue "Checking robot service now"

    $roboService = Get-Service -DisplayName "UiPath Robot"
    $roboState = $roboService.Status
    Write-Host "Robo status is: $roboState"
    Log-Write -LogPath $sLogFile -LineValue "Robo status is: $roboState"

    if ($roboService.Status -eq "Stopped" ) {
      Write-Host "Robot service was stopped, starting and waiting for it now"
      Log-Write -LogPath $sLogFile -LineValue "Robot service was stopped, starting and waiting for it now"
      Start-Service $roboService.Name
    }
    # Wait for the service to reach the $serviceStatus or a maximum of specified time
    $robotService.WaitForStatus("Running", $timeLength)
    
  }
  End {
      If($?){
        Write-Host "Completed Successfully."
          Log-Write -LogPath $sLogFile -LineValue "Completed Successfully."
          Write-Host " "
          Log-Write -LogPath $sLogFile -LineValue " "
      }
  }

}

<#
  .DESCRIPTION
  Installs an MSI by calling msiexec.exe, with verbose logging
  .PARAMETER msiPath
  Path to the MSI to be installed
  .PARAMETER logPath
  Path to a file where the MSI execution will be logged via "msiexec [...] /lv*"
  .PARAMETER features
  A list of features that will be installed via ADDLOCAL="..."
  .PARAMETER properties
  Additional MSI properties to be passed to msiexec
#>
function Invoke-MSIExec {

      param (
          [Parameter(Mandatory = $true)]
          [string] $msiPath,

          [Parameter(Mandatory = $true)]
          [string] $logPath,

          [string[]] $features,

          [System.Collections.Hashtable] $properties
      )

      if (!(Test-Path $msiPath)) {
          throw "No .msi file found at path '$msiPath'"
      }

      $msiExecArgs = "/i `"$msiPath`" /q /lv* `"$logPath`" "

      if ($features) {
          $msiExecArgs += "ADDLOCAL=`"$($features -join ',')`" "
      }

      if ($properties) {
          $msiExecArgs += (($properties.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " ")
      }

      $process = Start-Process "msiexec" -ArgumentList $msiExecArgs -Wait -PassThru

      return $process
}

<#
  .DESCRIPTION
  Gets the path to the UiRobot.exe file
  .PARAMETER community
  Whether to search for the UiPath Studio Community edition executable
#>
function Get-UiRobotExePath {
      param(
          [switch] $community
      )

      $robotExePath = [System.IO.Path]::Combine(${ENV:ProgramFiles(x86)}, "UiPath", "Studio", "UiRobot.exe")

      if ($community) {
          $robotExePath = Get-ChildItem ([System.IO.Path]::Combine($ENV:LOCALAPPDATA, "UiPath")) -Recurse -Include "UiRobot.exe" | `
              Select-Object -ExpandProperty FullName -Last 1
      }

      return $robotExePath
}

<#
  .DESCRIPTION
  Downloads a file from a URL
  .PARAMETER url
  The URL to download from
  .PARAMETER outputFile
  The local path where the file will be downloaded
#>
function Download-File {
      param (
          [Parameter(Mandatory = $true)]
          [string]$url,

          [Parameter(Mandatory = $true)]
          [string] $outputFile
      )

      Write-Verbose "Downloading file from $url to local path $outputFile"

      $webClient = New-Object System.Net.WebClient

      $webClient.DownloadFile($url, $outputFile)

}

<#
  .DESCRIPTION
  Install UiPath Robot and/or Studio.
  .PARAMETER msiPath
  MSI installer path.
  .PARAMETER installationFolder
  Installation folder location.
  .PARAMETER msiFeatures
  MSI features : Robot with or without Studio
#>
function Install-UiPath {

      param (
          [Parameter(Mandatory = $true)]
          [string] $msiPath,

          [string] $installationFolder,

          [string[]] $msiFeatures
      )

      if (!$msiProperties) {
          $msiProperties = @{}
      }

      if ($installationFolder) {
          Write-Host "Install-UiPath attempting to install UiPath at path $installationFolder"
          $msiProperties["APPLICATIONFOLDER"] = $installationFolder;
      }
      Else {
          Write-Host "Installing UiPath at default path"
      }

      $logPath = Join-Path $script:tempDirectory "install.log"
      $process = Invoke-MSIExec -msiPath $msiPath -logPath $logPath -features $msiFeatures

      return @{
          LogPath = $logPath;
          MSIExecProcess = $process;
      }
}

<#
  .SYNOPSIS
    Creates log file
  .DESCRIPTION
    Creates log file with path and name that is passed. Checks if log file exists, and if it does deletes it and creates a new one.
    Once created, writes initial logging data
  .PARAMETER LogPath
    Mandatory. Path of where log is to be created. Example: C:\Windows\Temp
  .PARAMETER LogName
    Mandatory. Name of log file to be created. Example: Test_Script.log
  .PARAMETER ScriptVersion
    Mandatory. Version of the running script which will be written in the log. Example: 1.5
  .INPUTS
    Parameters above
  .OUTPUTS
    Log file created
 #>
function Log-Start {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [string]$LogName,

        [Parameter(Mandatory=$true)]
        [string]$ScriptVersion
    )

    Process{
      $sFullPath = $LogPath + "\" + $LogName

      #Check if file exists and delete if it does
      If((Test-Path -Path $sFullPath)){
        Remove-Item -Path $sFullPath -Force
      }

      #Create file and start logging
      New-Item -Path $LogPath -Value $LogName -ItemType File

      Add-Content -Path $sFullPath -Value "***************************************************************************************************"
      Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
      Add-Content -Path $sFullPath -Value "***************************************************************************************************"
      Add-Content -Path $sFullPath -Value ""
      Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
      Add-Content -Path $sFullPath -Value ""
      Add-Content -Path $sFullPath -Value "Running with debug mode [$sDebug]."
      Add-Content -Path $sFullPath -Value ""
      Add-Content -Path $sFullPath -Value "***************************************************************************************************"
      Add-Content -Path $sFullPath -Value ""

      #Write to screen for debug mode
      Write-Debug "***************************************************************************************************"
      Write-Debug "Started processing at [$([DateTime]::Now)]."
      Write-Debug "***************************************************************************************************"
      Write-Debug ""
      Write-Debug "Running script version [$ScriptVersion]."
      Write-Debug ""
      Write-Debug "Running with debug mode [$sDebug]."
      Write-Debug ""
      Write-Debug "***************************************************************************************************"
      Write-Debug ""
    }

}


<#
  .SYNOPSIS
    Writes to a log file
  .DESCRIPTION
    Appends a new line to the end of the specified log file
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
  .PARAMETER LineValue
    Mandatory. The string that you want to write to the log
  .INPUTS
    Parameters above
  .OUTPUTS
    None
#>
function Log-Write {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [string]$LineValue
    )

    Process{
      Add-Content -Path $LogPath -Value $LineValue

      #Write to screen for debug mode
      Write-Debug $LineValue
    }
}

<#
  .SYNOPSIS
    Writes an error to a log file
  .DESCRIPTION
    Writes the passed error to a new line at the end of the specified log file
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
  .PARAMETER ErrorDesc
    Mandatory. The description of the error you want to pass (use $_.Exception)
  .PARAMETER ExitGracefully
    Mandatory. Boolean. If set to True, runs Log-Finish and then exits script
  .INPUTS
    Parameters above
  .OUTPUTS
    None
#>
function Log-Error {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$true)]
        [string]$ErrorDesc,

        [Parameter(Mandatory=$true)]
        [boolean]$ExitGracefully
    )

    Process{
      Add-Content -Path $LogPath -Value "Error: An error has occurred [$ErrorDesc]."

      #Write to screen for debug mode
      Write-Debug "Error: An error has occurred [$ErrorDesc]."

      #If $ExitGracefully = True then run Log-Finish and exit script
      If ($ExitGracefully -eq $True){
        Log-Finish -LogPath $LogPath
        Break
      }
    }
}

<#
  .SYNOPSIS
    Write closing logging data & exit
  .DESCRIPTION
    Writes finishing logging data to specified log and then exits the calling script
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write finishing data to. Example: C:\Windows\Temp\Script.log
  .PARAMETER NoExit
    Optional. If this is set to True, then the function will not exit the calling script, so that further execution can occur
  .INPUTS
    Parameters above
  .OUTPUTS
    None
#>
function Log-Finish {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$false)]
        [string]$NoExit
    )

    Process{
      Add-Content -Path $LogPath -Value ""
      Add-Content -Path $LogPath -Value "***************************************************************************************************"
      Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
      Add-Content -Path $LogPath -Value "***************************************************************************************************"
      Add-Content -Path $LogPath -Value ""

      #Write to screen for debug mode
      Write-Debug ""
      Write-Debug "***************************************************************************************************"
      Write-Debug "Finished processing at [$([DateTime]::Now)]."
      Write-Debug "***************************************************************************************************"
      Write-Debug ""

      #Exit calling script if NoExit has not been specified or is set to False
      If(!($NoExit) -or ($NoExit -eq $False)){
        Exit
      }
    }
}


Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
Main
Log-Finish -LogPath $sLogFile