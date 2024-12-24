<#
    .SYNOPSIS
    This script performs the installation or uninstallation of an application(s).
    # LICENSE #
    PowerShell App Deployment Toolkit - Provides a set of functions to perform common application deployment tasks on Windows.
    Copyright (C) 2017 - Sean Lillis, Dan Cunningham, Muhammad Mashwani, Aman Motazedian.
    This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
    You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
    .DESCRIPTION
    The script is provided as a template to perform an install or uninstall of an application(s).
    The script either performs an "Install" deployment type or an "Uninstall" deployment type.
    The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.
    The script dot-sources the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.
    .PARAMETER DeploymentType
    The type of deployment to perform. Default is: Install.
    .PARAMETER DeployMode
    Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set if it is detected that the process is not user interactive.
    .PARAMETER AllowRebootPassThru
    Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.
    .PARAMETER TerminalServerMode
    Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Destkop Session Hosts/Citrix servers.
    .PARAMETER DisableLogging
    Disables logging to file for the script. Default is: $false.
    .EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeployMode 'Silent'; Exit $LastExitCode }"
    .EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -AllowRebootPassThru; Exit $LastExitCode }"
    .EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeploymentType 'Uninstall'; Exit $LastExitCode }"
    .EXAMPLE
    Deploy-Application.exe -DeploymentType "Install" -DeployMode "Silent"
    .NOTES
    Toolkit Exit Code Ranges:
    60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
    69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
    70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
    .LINK
    http://psappdeploytoolkit.com
    .LINK
    https://www.dell.com/support/kbdoc/en-us/000177292/how-to-create-a-dell-command-update-msi-installer-package
    .NOTES
    In order to extract the download Dell Command Update executable, follow directions at the link above or use the example command below
    Dell-Command-Update_Y2PJJ_WIN_3.1.1_A00.EXE /passthrough /x /b"C:\Temp\DCU3.1"
#>
  [CmdletBinding()]
    Param
      (
          [Parameter(Mandatory = $False)]
          [ValidateSet('Install', 'Uninstall', 'Repair')]
          [String]$DeploymentType = 'Install',

          [Parameter(Mandatory = $False)]
          [ValidateSet('Interactive', 'Silent', 'NonInteractive')]
          [String]$DeployMode = 'Interactive',

          [Parameter(Mandatory = $False)]
          [Switch]$AllowRebootPassThru = $False,

          [Parameter(Mandatory = $False)]
          [Switch]$TerminalServerMode = $False,

          [Parameter(Mandatory = $False)]
          [Switch]$DisableLogging = $False,

          ########Custom Parameters##########

            [Parameter(Mandatory=$False)]
            [Switch]$UpdateDrivers,

            [Parameter(Mandatory=$False)]
            [Alias('DCUDD', 'DD')]
            [System.IO.DirectoryInfo]$DCUDownloadDirectory,

            [Parameter(Mandatory=$False)]
            [Alias('ME', 'DE')]
            [Regex]$ManufacturerExpression = ".*Dell.*",
            
            [Parameter(Mandatory=$False)]
            [Switch]$StageContent,

            [Parameter(Mandatory=$False)]
            [System.IO.DirectoryInfo]$ContentStagingPath
    
          ###################################
      )

Try {
  ## Set the script execution policy for this process
  Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}
  
  ## Set any required variable(s)
    $OSArch = (Get-WmiObject -Namespace 'Root\CIMv2' -Class 'Win32_OperatingSystem' -Property 'OSArchitecture' | Select-Object -ExpandProperty 'OSArchitecture' | Out-String).Replace("-bit", "").Replace("32", "86").Insert(0,"x").ToUpperInvariant()

  ##*===============================================
  ##* VARIABLE DECLARATION
  ##*===============================================
  ## Variables: Application
    [String]$Custom_AppVendor = "Dell"
    [String]$Custom_AppName = "Command Update"
    [String]$Custom_AppVersion = "5.4.0"
      
    [string]$appVendor = "$($Custom_AppVendor)"
    [string]$appName = "$($Custom_AppName)"
    [string]$appVersion = "$($Custom_AppVersion)"
    [string]$appArch = "$($OSArch)"
    [string]$appLang = "$((Get-Culture).Name)"
    [string]$appRevision = '01'
    [string]$appScriptVersion = '1.0.0'
    [string]$appScriptDate = '12/23/2024'
    [string]$appScriptAuthor = 'Grace Solutions'
  ##*===============================================
  ## Variables: Install Titles (Only set here to override defaults set by the toolkit)
  [string]$installName = ''
  [string]$installTitle = "$($Custom_AppVendor) $($Custom_AppName) [Version: $($Custom_AppVersion)]"

  ##* Do not modify section below
  #region DoNotModify

  ## Variables: Exit Code
  [int32]$mainExitCode = 0

  ## Variables: Script
  [string]$deployAppScriptFriendlyName = 'Deploy Application'
  [version]$deployAppScriptVersion = [version]'3.8.4'
  [string]$deployAppScriptDate = '26/01/2021'
  [hashtable]$deployAppScriptParameters = $psBoundParameters

  ## Variables: Environment
      If (Test-Path -LiteralPath 'variable:HostInvocation') {$InvocationInfo = $HostInvocation} Else {$InvocationInfo = $MyInvocation}
      [System.IO.DirectoryInfo]$ScriptDirectory = Split-Path -Path "$($InvocationInfo.MyCommand.Definition)" -Parent

  ## Dot source the required App Deploy Toolkit Functions
  Try {
    [System.IO.FileInfo]$ModuleAppDeployToolkitMain = "$($ScriptDirectory.FullName)\AppDeployToolkit\AppDeployToolkitMain.ps1"
    If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$moduleAppDeployToolkitMain]." }
    If ($DisableLogging) { . $moduleAppDeployToolkitMain -DisableLogging } Else { . $moduleAppDeployToolkitMain }
  }
  Catch {
    If ($mainExitCode -eq 0){ [int32]$mainExitCode = 60008 }
    Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
    ## Exit the script, returning the exit code to SCCM
    If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $mainExitCode; Exit } Else { Exit $mainExitCode }
  }

  #endregion
  ##* Do not modify section above
  ##*===============================================
  ##* END VARIABLE DECLARATION
  ##*===============================================
  
  #Change Directory Location
      Set-Location -Path "$($ScriptDirectory)" -Verbose -ErrorAction Continue

  #Define the product name for software detection/removal
    [Regex]$ProductName = "^Dell.*Command.*Update.*$"
    [Regex]$ProductNameExclusions = "(^.{0,0}$)"  
  
  #Processes to close if they are running during deployment
      $ProcessesToClose = "dcu-cli,DellCommandUpdate,InvColPC,ServiceShell"

  If ($deploymentType -ine 'Uninstall' -and $deploymentType -ine 'Repair') {
    ##*===============================================
    ##* PRE-INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Pre-Installation'

    ## <Perform Pre-Installation tasks here>
    
        #Log hardware information
          $MSSystemInformation = Get-WmiObject -Namespace "root\WMI" -Class "MS_SystemInformation" -Property * | Select-Object -Property *
          
          $MSSystemInformationMembers = $MSSystemInformation | Get-Member | Where-Object {($_.MemberType -imatch '^NoteProperty$|^Property$') -and ($_.Name -imatch '^Base.*|Bios.*|System.*$') -and ($_.Name -inotmatch '^.*Major.*|.*Minor.*|.*Properties.*$')} | Sort-Object -Property @('Name')
  
          $LogMessage = "Attempting to display device information properties from the `"$($MSSystemInformation.__CLASS)`" WMI class located within the `"$($MSSystemInformation.__NAMESPACE)`" WMI namespace. Please Wait..."
          Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "Get-DeviceInfo" -ContinueOnError:$True
  
          ForEach ($MSSystemInformationMember In $MSSystemInformationMembers)
            {
                [String]$MSSystemInformationMemberName = ($MSSystemInformationMember.Name)
                [String]$MSSystemInformationMemberValue = $MSSystemInformation.$($MSSystemInformationMemberName)
        
                Switch ([String]::IsNullOrEmpty($MSSystemInformationMemberValue))
                  {
                      {($_ -eq $False)}
                        {
                            $LogMessage = "$($MSSystemInformationMemberName): $($MSSystemInformationMemberValue)"
                            Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "Get-DeviceInfo" -ContinueOnError:$True
                        }
                  }
            }

        #Ensure that the device this script is being executed on is manufactured by devices matching the manufacturer regular expression       
          Switch (($MSSystemInformation.BaseBoardManufacturer -inotmatch $ManufacturerExpression.ToString()) -or ($MSSystemInformation.SystemManufacturer -inotmatch $ManufacturerExpression.ToString()))
            {
                {($_ -eq $True)}
                  {
                      $LogMessage = "Device Manufacturer: $($MSSystemInformation.BaseBoardManufacturer)"
                      Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "Invalid-Manufacturer" -ContinueOnError:$True
                      
                      $LogMessage = "Motherboard Manufacturer: $($MSSystemInformation.SystemManufacturer)"
                      Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "Invalid-Manufacturer" -ContinueOnError:$True
                      
                      $LogMessage = "Manufacturer Expression: $($ManufacturerExpression.ToString())"
                      Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "Invalid-Manufacturer" -ContinueOnError:$True
              
                      $LogMessage = "Invalid device manufacturer detected! Please ensure that this script is executed on devices manufactured by Dell only!"
                      Write-Log -Message "$($LogMessage)" -Severity 3 -LogType CMTrace -Source "Invalid-Manufacturer" -ContinueOnError:$True
                                    
                      Exit-Script -ExitCode 70001
                  }
                  
                {($_ -eq $False)}
                  {
                      $LogMessage = "Device manufacturer matches `"$($ManufacturerExpression.ToString())`"."
                      Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "Invalid-Manufacturer" -ContinueOnError:$True
                  }
            }
    
        #Optionally stage the content onto the hard disk for later use
          If ($StageContent.IsPresent -eq $True)
            {
                Try
                  {                            
                      #Display an installation progress window (This will not show up if the process is launched non-interactively)
                        Show-InstallationProgress -StatusMessage "Now staging content.`r`n$($Custom_AppVendor) $($Custom_AppName)`r`n$($Custom_AppVersion)`r`nPlease Wait..." -WindowLocation BottomRight -TopMost:$True
                  
                      If ((!$PSBoundParameters.ContainsKey('ContentStagingPath')) -and ([String]::IsNullOrEmpty($ContentStagingPath.FullName)))
                        {
                            [System.IO.DirectoryInfo]$ContentStagingPath = "$($EnvSystemDrive)\StagedContent\Applications\$($AppVendor)\$($AppName)\$($AppVersion)"
                        }
                        
                      $LogMessage = "Attempting to stage the application content in the following location. Please Wait...`r`n`r`nContentStagingPath = `"$($ContentStagingPath.FullName)`""
                      Write-Log -Message "$($LogMessage)" -Severity 2 -LogType CMTrace -Source "Stage-Content" -ContinueOnError:$True
                            
                      If ($ContentStagingPath.Exists -eq $False) {New-Folder -Path $ContentStagingPath.FullName -ContinueOnError:$False -Verbose}

                      [System.IO.FileInfo]$BinaryPath = "$($envSystem32Directory)\Robocopy.exe"
                      [System.IO.DirectoryInfo]$BinaryWorkingDirectory = "$($BinaryPath.Directory.FullName)"
                      [System.IO.FileInfo]$BinaryLogPath = "$($DCULogDirectory.FullName)\Robocopy\StageContent_$($Custom_AppVendor)_$($Custom_AppName)_$($Custom_AppVersion)_$($GetCurrentDateTimeFileFormat.Invoke()).log"
                      [String]$BinaryParameters = "`"$($ScriptDirectory)`" `"$($ContentStagingPath.FullName)`" /MIR /Z /ZB /W:5 /R:3 /J /NP /FP /TS /NDL /XX /TEE /MT:8 /LOG:`"$($BinaryLogPath.FullName)`""

                      If ($BinaryLogPath.Directory.Exists -eq $False) {New-Folder -Path "$($BinaryLogPath.Directory.FullName)" -Verbose -ContinueOnError:$False}
                                                                                                          
                      $PerformContentStaging = Execute-Process -Path "$($BinaryPath.FullName)" -WorkingDirectory "$($BinaryWorkingDirectory.FullName)" -Parameters "$($BinaryParameters)" -CreateNoWindow -PassThru -ContinueOnError:$True -ExitOnProcessFailure:$False
                      
                      If ([String]::IsNullOrEmpty($PerformContentStaging.StdOut) -eq $False)
                        {
                            $LogMessage = "See the standard output for $($BinaryPath.Name) below.`r`n`r`n$($PerformContentStaging.StdOut)"
                            Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($BinaryPath.BaseName)-StdOut" -ContinueOnError:$True
                        }
                      
                      $StagedContent = Get-ChildItem -Path "$($ContentStagingPath.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue
                  }
                Catch
                  {
                      $ErrorMessage = "[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                      Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "Stage-Content" -ContinueOnError:$True
                  }
            }
            
          #Determine if a task sequence is running
            Try
              {
                  [System.__ComObject]$TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment"
              
                  If ($Null -ine $TSEnvironment)
                    {
                        [Boolean]$IsRunningTaskSequence = $True
                        
                        [String]$LogMessage = "A task sequence is CURRENTLY running."
                        Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "TaskSequenceRunning-$($IsRunningTaskSequence)" -ContinueOnError:$True
                      
                        [Boolean]$IsConfigurationManagerTaskSequence = [String]::IsNullOrEmpty($TSEnvironment.Value("_SMSTSPackageID")) -eq $False
                        
                        Switch ($IsConfigurationManagerTaskSequence)
                          {
                              {($_ -eq $True)}
                                {
                                    [String]$LogMessage = "Task Sequence Type: Configuration Manager"
                                    [String]$LogSource = "TaskSequenceType-MECM"
                                }
                                
                              {($_ -eq $False)}
                                {
                                    [String]$LogMessage = "Task Sequence Type: Microsoft Deployment Toolkit"
                                    [String]$LogSource = "TaskSequenceType-MDT"
                                }
                          }
                        
                        Write-Log -Message "$($LogMessage)" -Severity 1 -LogType CMTrace -Source "$($LogSource)" -ContinueOnError:$True
                    }         
              }
            Catch
              {
                  [Boolean]$IsRunningTaskSequence = $False
                  
                  [String]$LogMessage = "A task sequence is NOT currently running."
                  Write-Log -Message "$($LogMessage)" -Severity 2 -LogType CMTrace -Source "TaskSequenceRunning-$($IsRunningTaskSequence)" -ContinueOnError:$True
              }
                 
        #Display an installation progress window (This will not show up if the process is launched non-interactively)
          Show-InstallationProgress -StatusMessage "Now $($DeploymentType.ToLowerInvariant())ing`r`n$($Custom_AppVendor) $($Custom_AppName)`r`n$($Custom_AppVersion)`r`nPlease Wait..." -WindowLocation BottomRight -TopMost:$True    

    ##*===============================================
    ##* INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Installation'
                                              
    ## <Perform Installation tasks here>
    
        [System.IO.DirectoryInfo]$DCUInstallerDirectory = "$($ContentDirectory.FullName)"
        
        $DCUInstallers = Get-ChildItem -Path "$($DCUInstallerDirectory.FullName)" -Filter "Dell*Command*Update*.msi" -Force | Where-Object {($_ -is [System.IO.FileInfo])} | Sort-Object -Property @('LastWriteTime')
        
        $DCUInstallerCount = $DCUInstallers | Measure-Object | Select-Object -ExpandProperty Count
        
        $LogMessage = "Found $($DCUInstallerCount) DCU MSI installer(s) located within `"$($DCUInstallerDirectory.FullName)`". Only the latest one will be installed if necessary."
        Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DCUInstaller-Count-$($DCUInstallerCount)" -ContinueOnError:$True
        
        Switch ($DCUInstallerCount -gt 0)
          {
              {($_ -eq $True)}
                {
                    [System.IO.FileInfo]$LatestDCUInstaller = $DCUInstallers | Select-Object -First 1
                    
                    $LatestDCUInstallerInfo = Get-MSITableProperty -Path ($LatestDCUInstaller.FullName)
                        
                    [String]$ExecuteMSI_Action = 'Install'
                    [System.IO.FileInfo]$ExecuteMSI_Path = "$($LatestDCUInstaller.FullName)"
                    [String]$ExecuteMSI_AddParameters = ""
                    [Switch]$ExecuteMSI_SkipMSIAlreadyInstalledCheck = $False
                    [Switch]$ExecuteMSI_PassThru = $True
                    [String]$ExecuteMSI_IgnoreExitCodes = '3010'
                    [Bool]$ExecuteMSI_ExitOnProcessFailure = $True
                    [Bool]$ExecuteMSI_ContinueOnError = $False

                    [Hashtable]$ExecuteMSIParameters = @{}
                      $ExecuteMSIParameters.Add('Action', ($ExecuteMSI_Action))
                      $ExecuteMSIParameters.Add('Path', ($ExecuteMSI_Path))
                      $ExecuteMSIParameters.Add('SkipMSIAlreadyInstalledCheck', ($ExecuteMSI_SkipMSIAlreadyInstalledCheck))
                      $ExecuteMSIParameters.Add('PassThru', ($ExecuteMSI_PassThru))
                      If ([String]::IsNullOrEmpty($ExecuteMSI_IgnoreExitCodes) -eq $False) {$ExecuteMSIParameters.Add('IgnoreExitCodes', ($ExecuteMSI_IgnoreExitCodes))}
                      $ExecuteMSIParameters.Add('ExitOnProcessFailure', ($ExecuteMSI_ExitOnProcessFailure))
                      $ExecuteMSIParameters.Add('ContinueOnError', ($ExecuteMSI_ContinueOnError))
                      
                    Switch ($True)
                      {
                          {([String]::IsNullOrEmpty($ExecuteMSI_AddParameters) -eq $False)}
                            {
                                $ExecuteMSIParameters.Add('AddParameters', ($ExecuteMSI_AddParameters))
                            }
                            
                          {($ExecuteMSI_Path.Exists -eq $False)}
                            {
                                $LogMessage = "Unable to locate DCU MSI installation binary `"$($ExecuteMSI_Path.FullName)`". No further action will be taken."
                                Write-Log -Message $LogMessage -Severity 3 -LogType CMTrace -Source "DCU-MSI-Missing" -ContinueOnError:$True
                                
                                Exit-Script -ExitCode 70002
                            }
                              
                          {($ExecuteMSI_Path.Exists -eq $True)}
                            {
                                $LogMessage = "Attempting to execute `"$($LatestDCUInstallerInfo.ProductName)`" [$($ExecuteMSI_Path.Name)] [Version: $($LatestDCUInstallerInfo.ProductVersion)]. Please Wait..."
                                Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "Execute-DCU-MSI" -ContinueOnError:$True
                        
                                $ExecuteMSIInfo = Execute-MSI @ExecuteMSIParameters
                            }
                      }
                      
                    [Int]$SecondsToWait = 3

                    $LogMessage = "Pausing script execution for $($SecondsToWait) second(s). Please Wait..."
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Pause-Execution-$($SecondsToWait)" -ContinueOnError:$True
                                      
                    $Null = Start-Sleep -Seconds ($SecondsToWait)
                    
                    [String[]]$Services = @('DellClientManagementService')
                    
                    [String]$DesiredServiceStartMode = 'Automatic (Delayed Start)'
                    
                    ForEach ($Service In $Services)
                      {
                          Switch ($Null -ine (Get-Service -Name $Service -ErrorAction SilentlyContinue))
                            {
                                {($_ -eq $True)}
                                  {
                                      $ServiceStartMode = Get-ServiceStartMode -Name ($Service)

                                      Switch ($ServiceStartMode -ine $DesiredServiceStartMode)
                                        {
                                            {($_ -eq $True)}
                                              {
                                                  $Null = Set-ServiceStartMode -Name ($Service) -StartMode ($DesiredServiceStartMode)
                                              }
                                        }
                                  }
                            }
                      }
  
                    $DCUInstallationInfo = Get-InstalledApplication -Name ($ProductName) -RegEx | Sort-Object @({[Version]($_.DisplayVersion)}) -Descending | Select-Object -First 1

                    [System.IO.FileInfo]$DCUPath = "$($DCUInstallationInfo.InstallLocation.TrimEnd('\'))\dcu-cli.exe"
                    
                    [System.IO.DirectoryInfo]$DCULogDirectory = "$($ConfigToolkitLogDir)"
                    
                    [System.IO.DirectoryInfo]$DCUSettingsDirectory = "$($DCULogDirectory.Parent.FullName)\Settings"
                    
                    Switch ($True)
                      {
                          {($Null -ieq $DCUDownloadDirectory)}
                            {
                                [System.IO.DirectoryInfo]$DCUDownloadDirectory = "$($DCULogDirectory.Parent.FullName)\Downloads"
                            }
                      }
                    
                    Switch (Test-Path -Path $DCUPath.FullName)
                      {
                          {($_ -eq $True)}
                            {        
                                [DateTime]$CurrentDate = (Get-Date)
                                [Int]$Year = $CurrentDate.Year
                                [Int]$Month = $CurrentDate.Month
                                [Int]$NumberOfDaysInMonth = [DateTime]::DaysInMonth($Year, $Month)
                                
                                [Int]$RandomDayOfMonth = @(1..$NumberOfDaysInMonth) | Get-Random
                                [Int]$RandomHourOfDay = @(0..23) | Get-Random
                                [Int]$RandomIncrementOfHour = @(0, 15, 30, 45) | Get-Random
                                
                                [String]$DCUSchedule = "$($RandomDayOfMonth.ToString('00')),$($RandomHourOfDay.ToString('00')):$($RandomIncrementOfHour.ToString('00'))"

                                $DCUCommands = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                  $DCUCommands.Add('Configure-restoreDefaults', "/configure -restoreDefaults")
                                  $DCUCommands.Add('Configure-userConsent', "/configure -userConsent=disable")
                                  $DCUCommands.Add('Configure-autoSuspendBitLocker', "/configure -autoSuspendBitLocker=enable")
                                  $DCUCommands.Add('Configure-updatetype', "/configure -updatetype=bios,firmware,driver,others")
                                  $DCUCommands.Add('Configure-updateDeviceCategory', "/configure -updateDeviceCategory=audio,video,network,storage,input,chipset,others")
                                  $DCUCommands.Add('Configure-updateSeverity', "/configure -updateSeverity=security,critical,recommended,optional")
                                  $DCUCommands.Add('Configure-advancedDriverRestore', "/configure -advancedDriverRestore=disable")
                                  $DCUCommands.Add('Configure-scheduleAction', "/configure -scheduleAction=DownloadInstallAndNotify")
                                  $DCUCommands.Add('Configure-scheduleMonthly', "/configure -scheduleMonthly=$($DCUSchedule)")
                                  $DCUCommands.Add('Configure-installationDeferral', "/configure -installationDeferral=enable -deferralInstallInterval=24 -deferralInstallCount=5")
                                  $DCUCommands.Add('Configure-systemRestartDeferral', "/configure -systemRestartDeferral=enable -deferralRestartInterval=1 -deferralRestartCount=8")
                                  $DCUCommands.Add('Configure-maxretry', "/configure -maxretry=2")
                                  $DCUCommands.Add('Configure-updatesNotification', "/configure -updatesNotification=enable")
                                  $DCUCommands.Add('Configure-lockSettings', "/configure -lockSettings=enable")
                                  $DCUCommands.Add('Configure-exportSettings', "/configure -exportSettings=`"$($DCUSettingsDirectory.FullName)`"")

                                Switch ($True)
                                  {
                                      {($UpdateDrivers.IsPresent -eq $True)}
                                        {
                                            $DCUCommands.Add('Scan-001', "/scan")
                                            $DCUCommands.Add('ApplyUpdates-001', "/applyUpdates -reboot=disable")
                                        }
                                  }

                                ForEach ($DCUCommand In ($DCUCommands.Keys))
                                  {
                                      [String]$DCUCommandName = $DCUCommand
                                      [String]$DCUCommandValue = $DCUCommands.$($DCUCommandName)
          
                                      [System.Text.StringBuilder]$DCUCommandParameters = New-Object -TypeName 'System.Text.StringBuilder'
                                        $Null = $DCUCommandParameters.Append($DCUCommandValue)
                                        
                                      $Null = $DCUCommandParameters.Append(' ').Append('-silent')

                                      Switch ($True)
                                        {                                                                  
                                            {($DCUCommandName -imatch '^Scan.*$')}
                                              {                          
                                                  [System.IO.DirectoryInfo]$DCUScanReportDirectory = "$($DCULogDirectory.Parent.FullName)\Reports"
                          
                                                  If ($DCUScanReportDirectory.Exists -eq $False) {$Null = New-Folder -Path ($DCUScanReportDirectory.FullName)}
                                                  
                                                  $DCUScanReports = Get-ChildItem -Path ($DCUScanReportDirectory.FullName) -Filter "*.xml" -Force | Where-Object {($_ -is [System.IO.FileInfo])} | Sort-Object -Property @('LastWriteTime') -Descending
                                                  
                                                  $DCUScanReportCount = $DCUScanReports | Measure-Object | Select-Object -ExpandProperty Count
                                                  
                                                  $LogMessage = "$($DCUScanReportCount) available update report(s) were found within `"$($DCUScanReportDirectory.FullName)`"."
                                                  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DCU-AvailableUpdate-Reports-$($DCUScanReportCount)" -ContinueOnError:$True
                                                  
                                                  Switch ($DCUScanReportCount -gt 0)
                                                    {
                                                        {($_ -eq $True)}
                                                          {                                                    
                                                              ForEach ($DCUScanReport In $DCUScanReports)
                                                                {
                                                                    $Null = Remove-File -Path "$($DCUScanReport.FullName)" -ContinueOnError:$True
                                                                }
                                                          }      
                                                    }  
                  
                                                  $Null = $DCUCommandParameters.Append(' ').Append("-report=`"$($DCUScanReportDirectory.FullName)`"")
                                              }
            
                                            {($DCUCommandParameters.ToString() -inotmatch ".*-outputlog\=.*")}
                                              {
                                                  [System.IO.FileInfo]$DCUOutputLogPath = "$($DCULogDirectory.FullName)\$($DCUCommandName).log"
                  
                                                  If ($DCUOutputLogPath.Directory.Exists -eq $False) {$Null = New-Folder -Path ($DCUOutputLogPath.Directory.FullName)}
                  
                                                  $Null = $DCUCommandParameters.Append(' ').Append("-outputLog=`"$($DCUOutputLogPath.FullName)`"")
                                              }
                                        }
            
                                      [System.IO.FileInfo]$ExecuteProcess_Path = ($DCUPath.FullName)
                                      [String]$ExecuteProcess_Parameters = ($DCUCommandParameters.ToString())
                                      [System.Diagnostics.Processwindowstyle]$ExecuteProcess_WindowStyle = [System.Diagnostics.Processwindowstyle]::Hidden 
                                      [Switch]$ExecuteProcess_PassThru = $True
                                      [Bool]$ExecuteProcess_ExitOnProcessFailure = $False
                                      [Bool]$ExecuteProcess_ContinueOnError = $False
                                      [String]$ExecuteProcess_IgnoreExitCodes = '1,5,3010'

                                      [Hashtable]$ExecuteProcessParameters = @{}
                                        $ExecuteProcessParameters.Add('Path', ($ExecuteProcess_Path))
                                        $ExecuteProcessParameters.Add('Parameters', ($ExecuteProcess_Parameters))
                                        $ExecuteProcessParameters.Add('WindowStyle', ($ExecuteProcess_WindowStyle))
                                        $ExecuteProcessParameters.Add('PassThru', ($ExecuteProcess_PassThru))
                                        $ExecuteProcessParameters.Add('ExitOnProcessFailure', ($ExecuteProcess_ExitOnProcessFailure))
                                        $ExecuteProcessParameters.Add('ContinueOnError', ($ExecuteProcess_ContinueOnError))
                                                                                  
                                        Switch ([String]::IsNullOrEmpty($ExecuteProcess_IgnoreExitCodes))
                                          {
                                              {($_ -eq $True)}
                                                {
                                                    [Regex]$ExecuteProcessExitCodeExpression = '^.{0,0}$'
                                                }
                                                
                                              {($_ -eq $False)}
                                                {
                                                    $ExecuteProcessParameters.Add('IgnoreExitCodes', ($ExecuteProcess_IgnoreExitCodes))
                                                    
                                                    [Regex]$ExecuteProcessExitCodeExpression = "^" + ($ExecuteProcess_IgnoreExitCodes -ireplace ',', '|') + "$"
                                                }
                                          }
                                          
                                      $LogMessage = "Attempting to execute `"$($DCUPath.VersionInfo.ProductName)`" [$($DCUPath.Name)] [Version: $($DCUPath.VersionInfo.ProductVersionRaw)] with parameters `"$($DCUCommandParameters.ToString())`""
                                      Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DCU-Execute-$($DCUCommandName)" -ContinueOnError:$True

                                      $ExecuteProcessInfo = Execute-Process @ExecuteProcessParameters
                                      
                                      [Int]$SecondsToWait = 3

                                      $LogMessage = "Pausing script execution for $($SecondsToWait) second(s). Please Wait..."
                                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Pause-Execution-$($SecondsToWait)" -ContinueOnError:$True
                                      
                                      $Null = Start-Sleep -Seconds ($SecondsToWait)
  
                                      Switch ($True)
                                        {
                                            {([String]::IsNullOrEmpty($ExecuteProcessInfo.STDOut) -eq $False)}
                                              {
                                                  $LogMessage = "Standard Output:`r`n$($ExecuteProcessInfo.STDOut)"
                                                  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DCU-$($DCUCommandName)-STDOutput" -ContinueOnError:$True
                                              }
                                  
                                            {([String]::IsNullOrEmpty($ExecuteProcessInfo.STDErr) -eq $False)}
                                              {
                                                  $LogMessage = "Standard Error:`r`n$($ExecuteProcessInfo.STDErr)"
                                                  Write-Log -Message $LogMessage -Severity 3 -LogType CMTrace -Source "DCU-$($DCUCommandName)-STDError" -ContinueOnError:$True
                                              }
                                              
                                            {($ExecuteProcessInfo.ExitCode -notin @(0)) -and ($ExecuteProcessInfo.ExitCode -imatch $ExecuteProcessExitCodeExpression.ToString())}
                                              {
                                                  Switch ($IsRunningTaskSequence)
                                                    {
                                                        {($_ -eq $True)}
                                                          {
                                                              $TaskSequenceVariablesToSet = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                          
                                                              Switch ($IsConfigurationManagerTaskSequence)
                                                                {
                                                                    {($_ -eq $True)}
                                                                      {
                                                                          $TaskSequenceVariablesToSet.Add('SMSTSRebootRequested', 'HD')
                                                                          $TaskSequenceVariablesToSet.Add('SMSTSRetryRequested', 'true')
                                                                      }
                                                          
                                                                    {($_ -eq $False)}
                                                                      {
                                                                          $TaskSequenceVariablesToSet.Add('SMSTSRebootRequested', 'true')
                                                                          $TaskSequenceVariablesToSet.Add('SMSTSRetryRequested', 'true')
                                                                      }
                                                                }

                                                              ForEach ($TaskSequenceVariableToSet In $TaskSequenceVariablesToSet.GetEnumerator())
                                                                {
                                                                    [String]$TaskSequenceVariableToSetName = "$($TaskSequenceVariableToSet.Key)"
                                                                    [String]$TaskSequenceVariableToSetValue = "$($TaskSequenceVariableToSet.Value)"
                                      
                                                                    [String]$LogMessage = "Attempting to set the task sequence variable of `"$($TaskSequenceVariableToSetName)`" to a value of `"$($TaskSequenceVariableToSetValue)`". Please Wait..."
                                                                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Set-TaskSequenceVariable" -ContinueOnError:$True
                                                                              
                                                                    $Null = $TSEnvironment.Value($TaskSequenceVariableToSetName) = "$($TaskSequenceVariableToSetValue)"       
                                                                }
                                                                
                                                              Exit-Script -ExitCode ($ExecuteProcessInfo.ExitCode)
                                                          }
                                                    }
                                              }
                                                                        
                                            {($ExecuteProcessInfo.ExitCode -notin @(0)) -and ($ExecuteProcessInfo.ExitCode -inotmatch $ExecuteProcessExitCodeExpression.ToString())}
                                              {
                                                  Exit-Script -ExitCode ($ExecuteProcessInfo.ExitCode)
                                              }
                                  
                                            {($DCUCommandName -imatch '^Scan.*$')}
                                              {                                                    
                                                  [Int]$SecondsToWait = 2

                                                  $LogMessage = "Pausing script execution for $($SecondsToWait) second(s). Please Wait..."
                                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Pause-Execution-$($SecondsToWait)" -ContinueOnError:$True
                                      
                                                  $Null = Start-Sleep -Seconds ($SecondsToWait)
                                                  
                                                  $DCUScanReports = Get-ChildItem -Path ($DCUScanReportDirectory.FullName) -Filter "*.xml" -Force | Where-Object {($_ -is [System.IO.FileInfo])} | Sort-Object -Property @('LastWriteTime') -Descending
                                                  
                                                  $DCUScanReportCount = $DCUScanReports | Measure-Object | Select-Object -ExpandProperty Count
                                                  
                                                  $LogMessage = "$($DCUScanReportCount) available update report(s) were found within `"$($DCUScanReportDirectory.FullName)`"."
                                                  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DCU-AvailableUpdate-Reports-$($DCUScanReportCount)" -ContinueOnError:$True
                                                  
                                                  Switch ($DCUScanReportCount -gt 0)
                                                    {
                                                        {($_ -eq $True)}
                                                          {
                                                              [System.IO.FileInfo]$DCUScanReportPath = $DCUScanReports | Select-Object -First 1
                                                    
                                                              [XML]$DCUScanReportInfo = [System.IO.File]::ReadAllText($DCUScanReportPath.FullName)
                          
                                                              $DCUAvailableUpdates = ($DCUScanReportInfo.Updates.Update) | Sort-Object -Property @({[DateTime]($_.Date)}) -Descending
                          
                                                              $DCUAvailableUpdateCount = $DCUAvailableUpdates | Measure-Object | Select-Object -ExpandProperty Count
                          
                                                              $LogMessage = "Found $($DCUAvailableUpdateCount) available update(s)."
                                                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "DCU-AvailableUpdateCount" -ContinueOnError:$True
                          
                                                              $DCUAvailableUpdateCounter = 1
                          
                                                              ForEach ($DCUAvailableUpdate In $DCUAvailableUpdates)
                                                                {
                                                                    [String]$DCUAvailableUpdateRelease = ($DCUAvailableUpdate.Release)
                                                                    [String]$DCUAvailableUpdateName = ($DCUAvailableUpdate.Name)
                                                                    $DCUAvailableUpdateVersion = Try {New-object -TypeName 'System.Version' -ArgumentList $DCUAvailableUpdate.Version} Catch {$DCUAvailableUpdate.Version}
                                                                    $DCUAvailableUpdateDate = Try {(Get-Date -Date ($DCUAvailableUpdate.Date)).ToString('dddd, MMMM dd, yyyy')} Catch {$DCUAvailableUpdate.Date}
                                                                    [String]$DCUAvailableUpdateUrgency = ($DCUAvailableUpdate.Urgency)
                                                                    [String]$DCUAvailableUpdateType = ($DCUAvailableUpdate.Type)
                                                                    [String]$DCUAvailableUpdateCategory = ($DCUAvailableUpdate.Category)
                                                            
                                                                    $LogMessage = "Update #$($DCUAvailableUpdateCounter.ToString('00')) - [Urgency: $($DCUAvailableUpdateUrgency)] - [Type: $($DCUAvailableUpdateType)] - [Category: $($DCUAvailableUpdateCategory)] - [Name: $($DCUAvailableUpdateName)] - [Release: $($DCUAvailableUpdateRelease)] - [Version: $($DCUAvailableUpdateVersion)] released on $($DCUAvailableUpdateDate)"
                                                                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "DCU-AvailableUpdate-$($DCUAvailableUpdateCounter.ToString('00'))" -ContinueOnError:$True
                                
                                                                    $Null = $DCUAvailableUpdateCounter++
                                                                }
                                                          }
                                                    }      
                                              }
                                        }
                                  }
                            }
                            
                          {($_ -eq $False)}
                            {
                                $LogMessage = "Unable to locate DCU CLI binary `"$($ExecuteMSI_Path.FullName)`". No further action will be taken."
                                Write-Log -Message $LogMessage -Severity 3 -LogType CMTrace -Source "DCU-CLI-Missing" -ContinueOnError:$True        
                            }
                      }
                }          
          }
    
    ##*===============================================
    ##* POST-INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Post-Installation'

    ## <Perform Post-Installation tasks here>

      
      
  }
  ElseIf ($deploymentType -ieq 'Uninstall')
  {
    ##*===============================================
    ##* PRE-UNINSTALLATION
    ##*===============================================
    [string]$installPhase = 'Pre-Uninstallation'

    #Display an installation progress window (This will not show up if the process is launched non-interactively)
      Show-InstallationProgress -StatusMessage "Now $($DeploymentType.ToLowerInvariant())ing`r`n$($Custom_AppVendor) $($Custom_AppName)`r`n$($Custom_AppVersion)`r`nPlease Wait..." -WindowLocation BottomRight -TopMost:$True

    ## <Perform Pre-Uninstallation tasks here>


    ##*===============================================
    ##* UNINSTALLATION
    ##*===============================================
    [string]$installPhase = 'Uninstallation'

    If (!([String]::IsNullOrEmpty($ProductName)))
      {
          If (!([String]::IsNullOrEmpty($ProcessesToClose)))
            {
                Uninstall-Application -ProductName "$($ProductName.ToString())" -ProductNameExclusions "$($ProductNameExclusions.ToString())" -PromptToCloseProcesses -ProcessesToClose $ProcessesToClose -ShowProgress
            }
          Else
            {
                Uninstall-Application -ProductName "$($ProductName.ToString())" -ProductNameExclusions "$($ProductNameExclusions.ToString())" -ShowProgress
            }
      }

    # <Perform Uninstallation tasks here>


    ##*===============================================
    ##* POST-UNINSTALLATION
    ##*===============================================
    [string]$installPhase = 'Post-Uninstallation'

    ## <Perform Post-Uninstallation tasks here>


  }
  ElseIf ($deploymentType -ieq 'Repair')
  {
    ##*===============================================
    ##* PRE-REPAIR
    ##*===============================================
    [string]$installPhase = 'Pre-Repair'

    #Display an installation progress window (This will not show up if the process is launched non-interactively)
      Show-InstallationProgress -StatusMessage "Now $($DeploymentType.ToLowerInvariant())ing`r`n$($Custom_AppVendor) $($Custom_AppName)`r`n$($Custom_AppVersion)`r`nPlease Wait..." -WindowLocation BottomRight -TopMost:$True

    ## <Perform Pre-Repair tasks here>

    ##*===============================================
    ##* REPAIR
    ##*===============================================
    [string]$installPhase = 'Repair'

    $ApplicationsToRepair = Get-InstalledApplication -Name "$($ProductName.ToString())" -RegEx | Where-Object {(!([String]::IsNullOrEmpty($_.ProductCode)))}
            
    ForEach ($Application In $ApplicationsToRepair)
      {
          $RepairApplication = Execute-MSI -Action Repair -Path "$($Application.ProductCode)" -ContinueOnError:$False
      }
                
    # <Perform Repair tasks here>

    ##*===============================================
    ##* POST-REPAIR
    ##*===============================================
    [string]$installPhase = 'Post-Repair'

    ## <Perform Post-Repair tasks here>


    }
  ##*===============================================
  ##* END SCRIPT BODY
  ##*===============================================

  ## Call the Exit-Script function to perform final cleanup operations
    #Log the total script execution time  
      $ScriptExecutionTimespan = New-TimeSpan -Start ($CurrentProcessAdvancedProperties.CreationDate) -End (Get-Date)

      $LogMessage = "Script execution took $($ScriptExecutionTimespan.Hours.ToString()) hour(s), $($ScriptExecutionTimespan.Minutes.ToString()) minute(s), $($ScriptExecutionTimespan.Seconds.ToString()) second(s), and $($ScriptExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ScriptExecutionTime-Total" -ContinueOnError:$True

    Exit-Script -ExitCode $mainExitCode
}
Catch
  {
      #Log the total script execution time  
        $ScriptExecutionTimespan = New-TimeSpan -Start ($CurrentProcessAdvancedProperties.CreationDate) -End (Get-Date)

        $LogMessage = "Script execution took $($ScriptExecutionTimespan.Hours.ToString()) hour(s), $($ScriptExecutionTimespan.Minutes.ToString()) minute(s), $($ScriptExecutionTimespan.Seconds.ToString()) second(s), and $($ScriptExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ScriptExecutionTime-Total" -ContinueOnError:$True

      [int32]$mainExitCode = 60001
      [string]$mainErrorMessage = "$(Resolve-Error)"
      Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
      Exit-Script -ExitCode $mainExitCode
  }
