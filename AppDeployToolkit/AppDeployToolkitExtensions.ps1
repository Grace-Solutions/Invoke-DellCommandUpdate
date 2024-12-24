<#
.SYNOPSIS
	This script is a template that allows you to extend the toolkit with your own custom functions.
    # LICENSE #
    PowerShell App Deployment Toolkit - Provides a set of functions to perform common application deployment tasks on Windows.
    Copyright (C) 2017 - Sean Lillis, Dan Cunningham, Muhammad Mashwani, Aman Motazedian.
    This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
    You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
.DESCRIPTION
	The script is automatically dot-sourced by the AppDeployToolkitMain.ps1 script.
.NOTES
    Toolkit Exit Code Ranges:
    60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
    69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
    70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
.LINK
	http://psappdeploytoolkit.com
#>
[CmdletBinding()]
Param (
)

##*===============================================
##* VARIABLE DECLARATION
##*===============================================

# Variables: Script
[string]$appDeployToolkitExtName = 'PSAppDeployToolkitExt'
[string]$appDeployExtScriptFriendlyName = 'App Deploy Toolkit Extensions'
[version]$appDeployExtScriptVersion = [version]'3.8.4'
[string]$appDeployExtScriptDate = '26/01/2021'
[hashtable]$appDeployExtScriptParameters = $PSBoundParameters

##*===============================================
##* FUNCTION LISTINGS
##*===============================================

#region Define Useful Variable(s)
#Define ASCII Characters    
    $Equals = [char]61
    $Space = [char]32
    $SingleQuote = [char]39
    $DoubleQuote = [char]34
    $NewLine = "`r`n"

#Load WMI Classes
    $Bios = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Bios" -Property * | Select-Object -Property *
    $Baseboard = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Baseboard" -Property * | Select-Object -Property *
    $ComputerSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystem" -Property * | Select-Object -Property *
    $ComputerSystemProduct = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystemProduct" -Property * | Select-Object -Property *
    $OperatingSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_OperatingSystem" -Property * | Select-Object -Property *
    $MSSystemInformation = Get-WmiObject -Namespace "root\WMI" -Class "MS_SystemInformation" -Property * | Select-Object -Property *

#Retrieve property values
    $ProcessUser = "$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    
    $Make = $ComputerSystem.Manufacturer
    
    Switch -Regex ($Make)
      {
          '.*Lenovo.*' {$Model = $ComputerSystemProduct.Version}
          '.*Microsoft.*' {$Model = $MSSystemInformation.SystemSKU}
          Default {$Model = $ComputerSystem.Model}
      }

    $OSArchitecture = $($OperatingSystem.OSArchitecture).Replace("-bit", "").Replace("32", "86").Insert(0,"x").ToUpper()
    Try {$OSCaption = "{1} {2} {3}" -f $($OperatingSystem.Caption).Split(" ").Trim()} Catch {}
    $OSPlatform = "$($OperatingSystem.OSArchitecture -ireplace '(-.+)', '')"
    $IsWindowsPE = Test-Path -Path "HKLM:\SYSTEM\ControlSet001\Control\MiniNT" -ErrorAction SilentlyContinue
    $OSVersion = [Version]$OperatingSystem.Version
    $OSVersionNumber = "{0}.{1}" -f $OperatingSystem.Version.ToString().Split('.')
    If ([Version]$OperatingSystem.Version -ge [Version]"10.0") {$OSReleaseID = Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "ReleaseID"}
    $PSVersion = [Version]$PSVersionTable.PSVersion
    $SerialNumber = $Bios.SerialNumber.ToUpper()
    [System.IO.DirectoryInfo]$AppDeployToolkitDirectory = Split-Path -Path "$($MyInvocation.MyCommand.Definition)" -Parent
    [System.IO.DirectoryInfo]$SourceDirectory = "$($AppDeployToolkitDirectory.Parent.FullName)\Source"
    [System.IO.DirectoryInfo]$ContentDirectory = "$($SourceDirectory.FullName)\Content"
    [System.IO.DirectoryInfo]$AdditionalFunctionsDirectory = "$($SourceDirectory.FullName)\Functions"
    [System.IO.DirectoryInfo]$ToolsDirectory = "$($SourceDirectory.FullName)\Tools"
    [System.IO.DirectoryInfo]$ToolsDirectory_Generic = "$($ToolsDirectory.FullName)\All"
    [System.IO.DirectoryInfo]$ToolsDirectory_ArchSpecific = "$($ToolsDirectory.FullName)\$($OSArchitecture)"
    [System.IO.DirectoryInfo]$ModulesDirectory = "$($SourceDirectory.FullName)\Modules"
    $DateTimeLogFormat = 'dddd, MMMM dd, yyyy hh:mm:ss tt'  ###Monday, January 01, 2019 10:15:34 AM###
    [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
    $DateTimeFileFormat = 'yyyyMMdd_hhmmsstt'  ###20190403_115354AM###
    [ScriptBlock]$GetDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
    [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
    $TextInfo = (Get-Culture).TextInfo

#Define additional variables
  [System.IO.FileInfo]$7ZPath = "$($ToolsDirectory_ArchSpecific.FullName)\7z.exe"
  [System.IO.FileInfo]$CMTracePath = "$($ToolsDirectory_ArchSpecific.FullName)\CMTrace.exe"
#endregion
            
#region Function Get-AdministrativePrivilege
    Function Get-AdministrativePrivilege
        {
            $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
            Write-Output -InputObject ($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        }
#endregion

#region Log Process Information
#Log process properties to the log for easier troubleshooting of how the process was launched
  $CurrentProcessProperties = [System.Diagnostics.Process]::GetCurrentProcess()
  $CurrentProcessAdvancedProperties = Get-CIMInstance -ClassName "Win32_Process" -Filter "ProcessID = `'$($CurrentProcessProperties.ID)`'"

  $LogMessage = "ProcessID: $($CurrentProcessAdvancedProperties.ProcessId)"
  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "GetCurrentProcessInfo" -ContinueOnError:$True

  $LogMessage = "ProcessCommandLine: $($CurrentProcessAdvancedProperties.CommandLine)"
  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "GetCurrentProcessInfo" -ContinueOnError:$True

  $LogMessage = "ProcessExecutionContext: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "GetCurrentProcessInfo" -ContinueOnError:$True

  $LogMessage = "IsProcessElevated: $((Get-AdministrativePrivilege).ToString())"
  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "GetCurrentProcessInfo" -ContinueOnError:$True

  $LogMessage = "ProcessStartTime: $($CurrentProcessAdvancedProperties.CreationDate.ToString($DateTimeLogFormat))"
  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "GetCurrentProcessInfo" -ContinueOnError:$True
#endregion

#region Function Import-BundledModules
#Import any modules contained in the specified path(s)
  Function Import-BundledModules
      {
          [CmdletBinding(SupportsShouldProcess=$True)]
       
            Param
              (
                  [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, Position = 0)]
                  [ValidateNotNullOrEmpty()]
                  [Alias('FullName')]
                  [System.IO.DirectoryInfo[]]$Path,
                  
                  #Inclusion filters will be combined using "OR"
                  [Parameter(Mandatory=$False)]
                  [ValidateNotNullOrEmpty()]
                  [Regex]$NameInclusions = "^(.*)$",

                  [Parameter(Mandatory=$False)]
                  [ValidateNotNullOrEmpty()]
                  [Regex]$VersionInclusions = "^\s",

                  #Exclusion filters will be combined using "AND"
                  [Parameter(Mandatory=$False)]
                  [ValidateNotNullOrEmpty()]
                  [Regex]$NameExclusions = "(^.{0,0}$)",

                  [Parameter(Mandatory=$False)]
                  [ValidateNotNullOrEmpty()]
                  [Regex]$VersionExclusions = "(^.{0,0}$)",
                  
                  [Parameter(Mandatory=$False)]
                  [Switch]$StageLocally,

                  [Parameter(Mandatory=$False)]
                  [Switch]$ContinueOnError
              )
                    
          Begin
            {
                [String]$CmdletName = $MyInvocation.MyCommand.Name 
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
            }
          
          Process
            {                   
                ForEach ($Item In $Path)
                  {
                      Try
                        {
                            If ($Item.Exists -eq $True)
                              {
                                  $ModulesToImport = Get-ChildItem -Path "$($Item.FullName)" -Force -ErrorAction SilentlyContinue | Where-Object -FilterScript {($_.Attributes -imatch '.*Directory.*')}

                                  $ModulesToImportCount = $ModulesToImport | Measure-Object | Select-Object -ExpandProperty Count

                                  If ($ModulesToImportCount -gt 0)
                                    {
                                        $LogMessage = "`'$($ModulesToImportCount)`' modules need to be imported from the following location `'$($Item.FullName)`'"
                                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                        
                                        [ScriptBlock]$FilterScript_Inclusions = {($_.Name -imatch $NameInclusions.ToString()) -or ($_.Version -imatch $VersionInclusions.ToString())}
                                        
                                        [ScriptBlock]$FilterScript_Exclusions = {($_.Name -inotmatch $NameExclusions.ToString()) -and ($_.Version -inotmatch $VersionExclusions.ToString())}
                                      
                                        ForEach ($Module In $ModulesToImport)
                                          {
                                              $ModuleProperties = Get-Module -Name "$($Module.FullName)" -ListAvailable -ErrorAction Stop | Where-Object -FilterScript ($FilterScript_Inclusions) | Where-Object -FilterScript ($FilterScript_Exclusions) | Sort-Object -Property Version -Descending | Select-Object -First 1 -Property *
                                            
                                              [System.IO.DirectoryInfo]$ModuleSourcePathProperties = $ModuleProperties.ModuleBase
                                                                                            
                                              If ($StageLocally.IsPresent -eq $True)
                                                {
                                                    [System.IO.DirectoryInfo]$ModuleTargetPathProperties = "$($PSHome)\Modules\$($ModuleProperties.Name)"

                                                    If ($ModuleTargetPathProperties.Exists -eq $False)
                                                      {
                                                          [System.IO.DirectoryInfo]$ModuleDestination = "$($ModuleTargetPathProperties.FullName)"
                                                          If ($ModuleDestination.Exists -eq $False) {New-Folder -Path "$($ModuleDestination.FullName)" -Verbose -ContinueOnError:$False}
                                                          Copy-File -Path "$($ModuleSourcePathProperties.FullName)\*" -Destination "$($ModuleDestination.FullName)\" -Recurse -ContinueOnError:$False -ContinueFileCopyOnError:$False
                                                          $ModuleProperties = Get-Module -Name "$($ModuleDestination.FullName)" -ListAvailable -ErrorAction Stop | Where-Object -FilterScript ($FilterScript_Inclusions) | Where-Object -FilterScript ($FilterScript_Exclusions) | Sort-Object -Property Version -Descending | Select-Object -First 1 -Property *
                                                      }
                                                    Else
                                                      {
                                                          $ModuleProperties = Get-Module -Name "$($ModuleTargetPathProperties.Parent.FullName)" -ListAvailable -ErrorAction Stop | Where-Object -FilterScript ($FilterScript_Inclusions) | Where-Object -FilterScript ($FilterScript_Exclusions) | Sort-Object -Property Version -Descending | Select-Object -First 1 -Property *
                                                      }
                                                }

                                              $LogMessage = "Attempting to import the powershell module `'$($ModuleProperties.Name)`' [Version: $($ModuleProperties.Version)]. Please Wait..."
                                              Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "ImportModule-$($ModuleProperties.Name)-$($ModuleProperties.Version.ToString())-Begin" -ContinueOnError:$True

                                              $LogMessage = "Module Path: `'$($ModuleProperties.Path)`'"
                                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ModulePath" -ContinueOnError:$True

                                              #Unblock all module files
                                                $ModuleFiles = Get-ChildItem -Path "$($ModuleSourcePathProperties.FullName)" -File -Recurse -Force
                                        
                                                $ModuleFileCount = $ModuleFiles | Measure-Object | Select-Object -ExpandProperty Count
                                          
                                                If ($ModuleFileCount -gt 0)
                                                   {
                                                      $LogMessage = "Attempting to unblock file(s) associated with the `'$($ModuleProperties.Name)`' powershell module. Please Wait..."
                                                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Unblock-File" -ContinueOnError:$True
                                            
                                                      ForEach ($File In $ModuleFiles)
                                                        {
                                                            $UnblockFile = Unblock-File -Path "$($File.FullName)" -ErrorAction Continue
                                                        }
                                                  }
                                        
                                              If (!(Get-Module -Name "$($ModuleProperties.Name)"))
                                                {
                                                    $ImportModule = Import-Module -Name "$($ModuleProperties.Path)" -Global -DisableNameChecking -Force -NoClobber -ErrorAction Stop
                                                }
                                
                                              $ModulePropertyOutput = ($ModuleProperties | Select-Object -ExcludeProperty Definition | Format-List | Out-String).TrimStart().TrimEnd()
                              
                                              $LogMessage = "The following properties were found for the powershell module `'$($ModuleProperties.Name)`'`r`n`r`n$($ModulePropertyOutput)"
                                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ModuleProperties" -ContinueOnError:$True
                                
                                              $LogMessage = "Import of the powershell module `'$($ModuleProperties.Name)`' [Version: $($ModuleProperties.Version)]. was successful."
                                              Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "ImportModule-$($ModuleProperties.Name)-$($ModuleProperties.Version.ToString())-Completed" -ContinueOnError:$True
                                          }
                                    }
                                  Else
                                    {
                                        $LogMessage = "`'$($ModulesToImportCount)`' modules need to be imported from the following location `'$($Item.FullName)`'"
                                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                    }
                              }
                          }
                      Catch
                        {
                            $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                            Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "ImportModule-$($ModuleProperties.Name)-$($ModuleProperties.Version.ToString())-Failed" -ContinueOnError:$True

                            If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                        }
                  }
            }
        
          End
            {                                        
                  Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                  Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
            }
      }
#endregion
        
#region Dot Source Additional Scripts
#Dot source any additional script(s) from the functions directory. This will provide flexibility to add additional functions without updating the extensions and maintain consistenty across multiple applications.
  Try
    {
        If ($AdditionalFunctionsDirectory.Exists -eq $True)
          {
              [String[]]$AdditionalFunctionsFilter = "*.ps1"
        
              $AdditionalFunctionsToImport = Get-ChildItem -Path "$($AdditionalFunctionsDirectory.FullName)" -Include ($AdditionalFunctionsFilter) -File -Recurse -Force | Where-Object {($_.Directory.FullName -imatch ".*\\Active$")}
        
              $AdditionalFunctionsToImportCount = $AdditionalFunctionsToImport | Measure-Object | Select-Object -ExpandProperty Count
        
              If ($AdditionalFunctionsToImportCount -gt 0)
                {
                    $LogMessage = "Attempting to dot source `"$($AdditionalFunctionsToImportCount.ToString())`" additional functions from the following directory.`r`n`r`nPath: `"$($AdditionalFunctionsDirectory.FullName)`""
                    Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DotSource-Functions" -ContinueOnError:$True
                    
                    ForEach ($AdditionalFunctionToImport In $AdditionalFunctionsToImport)
                      {
                          Try
                            {
                                $LogMessage = "Attempting to dot source the additional function `"$($AdditionalFunctionToImport.BaseName)`". Please Wait...`r`n`r`nFunction Path: `"$($AdditionalFunctionToImport.FullName)`""
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "DotSource-Function" -ContinueOnError:$True
                          
                                . "$($AdditionalFunctionToImport.FullName)"
                            }
                          Catch
                            {
                                $ErrorMessage = "[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "DotSource-Functions" -ContinueOnError:$True
                            }
                      }

                    $LogMessage = "Function dot sourcing was completed successfully."
                    Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DotSource-Functions" -ContinueOnError:$True
                }
              Else
                {
                    $LogMessage = "There are `"$($AdditionalFunctionsToImportCount.ToString())`" functions to dot source from the following directory.`r`n`r`nPath: `"$($AdditionalFunctionsDirectory.FullName)`""
                    Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DotSource-Functions" -ContinueOnError:$True
                }
          }
        Else
          {
              $LogMessage = "The additional functions directory does not exist.`r`n`r`nPath: `"$($AdditionalFunctionsDirectory.FullName)`""
              Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "DotSource-Functions" -ContinueOnError:$True
          }
    }
  Catch
    {
        $ErrorMessage = "[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
        Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "DotSource-Functions" -ContinueOnError:$True               
    }
#endregion

#region Function Receive-Module
<#
    .Synopsis
    Downloads a powershell module from the powershell gallery using NuGet
    .DESCRIPTION
    Handles all complexity behind making your script's module dependencies available during script execution
    .EXAMPLE
    Receive-Module -Name "ImportExcel"
    .EXAMPLE
    [String[]]$Modules = "ImportExcel", "AutoItX", "AutoLogon"
    Receive-Module -Name $Modules
#>
Function Receive-Module
  {
      [CmdletBinding()]
        Param
          (
              [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, Position=0)]
              [String[]]$Name
          )

      Begin
        {
            [String]$CmdletName = $MyInvocation.MyCommand.Name 
            Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
            Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
        }
      
      Process
        {
          $ImportedModules = @()  
      
          ForEach ($Module In $Name)
              {
                  Try
                    { 
                        $IsModuleImported = [Boolean](Get-Module -Name "$($Module)" -ErrorAction SilentlyContinue)

                        If ($IsModuleImported -eq $False)
                          {
                              Write-Log -Message "Attempting to import powershell module `'$($Module)`'" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              $ImportedModuleProperties = Import-Module -Name "$($Module)" -Global -DisableNameChecking -Force -PassThru -ErrorAction Stop
                          }
                        ElseIf ($IsModuleImported -eq $True)
                          {
                              $LogMessage = "The powershell module `'$($Module)`' has already been imported. No further importing is necessary."
                              Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          }    
                    }
                  Catch
                    {
                        $ErrorMessage = "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                        
                        Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                        
                        Try
                          {
                              Write-Log -Message "Attempting to download and install the powershell module `'$($Module)`' for all users from the powershell gallery. Please Wait..." -Severity 1 -LogType CMTrace -Source "Download-PowershellModule-$($Module)" -ContinueOnError:$True
                              
                              Try
                                {
                                    If (!(Get-PackageProvider -ListAvailable | Where-Object {$_.Name -imatch "NuGet"}))
                                      {
                                          Write-Log -Message "The Powershell Package Provider `'NuGet`' does not exist on `'$($envComputerNameFQDN)`' and will be downloaded and available for all users. Please Wait..." -Severity 1 -LogType CMTrace -Source "Download-PowershellPackageProvider" -ContinueOnError:$True
                                          Install-PackageProvider -Name @("NuGet") -Scope AllUsers -Force
                                      }
                                }
                              Catch
                                {
                                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "Download-PowershellPackageProvider" -ContinueOnError:$True
                                    Exit-Script -ExitCode (Get-AvailableExitCode)
                                }
                              
                              Install-Module -Name "$($Module)" -Scope AllUsers -AllowClobber -Force -ErrorAction Stop                          
                          }
                          Catch
                          {
                              $ErrorMessage = "Failed to download and install the powershell module `'$($Module)`'`n$($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                              Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "Download-PowershellModule-$($Module)" -ContinueOnError:$True
                              Exit-Script -ExitCode (Get-AvailableExitCode)
                          }
                          
                        Try
                          {
                              $IsModuleImported = [Boolean](Get-Module -Name "$($Module)" -ErrorAction SilentlyContinue)

                              If ($IsModuleImported -eq $False)
                                {
                                    Write-Log -Message "Attempting to import powershell module `'$($Module)`'" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                    $ImportedModuleProperties = Import-Module -Name "$($Module)" -Global -DisableNameChecking -Force -PassThru -ErrorAction Stop
                                }
                              ElseIf ($IsModuleImported -eq $True)
                                {
                                    $LogMessage = "The powershell module `'$($Module)`' has already been imported. No further importing is necessary."
                                    Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                }
                          }
                          Catch
                          {
                              $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                              Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              Exit-Script -ExitCode (Get-AvailableExitCode)
                          }
                          
                        $ImportedModules += $ImportedModuleProperties
                    }    
              }
              
          Write-Output -InputObject $ImportedModules
        }
        
      End
        {
              Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
        }
  }
#endregion

#region Function ConvertTo-Base64
      Function ConvertTo-Base64 
        { 
          [CmdletBinding(SupportsShouldProcess=$False)]
            Param
              (     
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ValidateNotNullOrEmpty()]
                [String]$String                        
              )
              
            Begin
                {
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
          
            Process
                  {
                    Try
                      {
                          $EncodedString = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($String))
                          
                          $LogMessage = "`'$($String)`' has been converted to the following Base64 encoded string`n`n`'$($EncodedString)`'"
                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          
                          Write-Output $EncodedString
                      }
                    Catch
                      {
                          $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                          Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      }
                  }

            End
              {                                        
                    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
              }
        }
#endregion

#region Function ConvertFrom-Base64
	
    #Decode a Base64 string to a plain text string
      Function ConvertFrom-Base64 
        {  
          [CmdletBinding(SupportsShouldProcess=$False)]
            Param
              (     
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidatePattern('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')]
                [String]$String                        
              )
              
            Begin
                {
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
          
            Process
                  {
                    Try
                      {
                          $DecodedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($String))
                                                            
                          $LogMessage = "`'$($String)`' has been converted from the following Base64 encoded string`n`n`'$($DecodedString)`'"
                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
				
                          Write-Output $DecodedString
                      }
                    Catch
                      {
                          $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                          Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      }
                  }

            End
              {                                        
                    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
              }
        }
#endregion

#region Function Save-File
    #Save File Using Windows Explorer
      Function Save-File
        {
          [CmdletBinding()]
            Param
              (
                [Parameter(Mandatory=$False)]
                [String]$Title = "Please select where to save file",
                
                [Parameter(Mandatory=$False)]
                [String]$DefaultExtension = ".log", 
                
                [Parameter(Mandatory=$False)]
                [String]$DefaultFileName = "LogFile", 
                
                [Parameter(Mandatory=$False)]
                [String]$Filter = "Log Files (*.log)|*.log| All Files (*.*)|*.*", 
                
                [Parameter(Mandatory=$False)]
                [String]$InitialDirectory,
                
                [Parameter(Mandatory=$False)]
                [Switch]$AppendCurrentDateTime,

                [Parameter(Mandatory=$False)]
                [Switch]$ContinueOnError
              )
              
            Begin
                {
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
          
              Process
                    {
                      Try
                        {
                            [Void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
              
                            If ((!($PSBoundParameters.ContainsKey('InitialDirectory'))) -and ([String]::IsNullOrEmpty($InitialDirectory)))
                              {
                                  $InitialDirectory = "$($EnvTemp.TrimEnd('\'))"
                              }
              
                            If (!(Test-Path -Path $InitialDirectory)) {New-Folder -Path $InitialDirectory -ContinueOnError:$False -Verbose}
					
                            $SaveFileDialog = New-Object 'System.Windows.Forms.SaveFileDialog'
                            
                            If ($AppendCurrentDateTime.IsPresent -eq $True)
                              {
                                  $DateTimeStringFormat = 'yyyyMMdd_hhmmsstt'
                                  $CurrentDateTime = (Get-Date).ToString($DateTimeStringFormat)
                                  $SaveFileDialog.FileName = "$($DefaultFileName)_$($CurrentDateTime)$($DefaultExtension)"
                              }
                            ElseIf ($AppendCurrentDateTime.IsPresent -eq $False)
                              {
                                  $SaveFileDialog.FileName = "$($DefaultFileName)$($DefaultExtension)"
                              }
                              
                            $SaveFileDialog.Filter = $Filter
                            $SaveFileDialog.InitialDirectory = $InitialDirectory
                            $SaveFileDialog.Title = $Title
                            
                            Try
                              {
                                  $LogMessage = "Attempting to minimize all windows. All minimized windows will be restored after the function `'$($CmdletName)`' has completed. Please Wait..."
                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                  $ShellApp.MinimizeAll()
                              }
                            Catch
                              {
                                  $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                  Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                  If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                              }
					
                            $ShowDialog = $SaveFileDialog.ShowDialog((New-Object 'System.Windows.Forms.Form' -Property @{TopMost = $True; TopLevel = $True}))
					
                            If ((!([String]::IsNullOrEmpty($SaveFileDialog.FileName))) -and ($ShowDialog.ToString() -ine "Cancel"))
                              {
                                  $ProvidedFileProperties = [System.IO.FileInfo[]]$SaveFileDialog.FileName
                                  $ProvidedFilePropertyOutput = ($ProvidedFileProperties | Format-List -Property * | Out-String).TrimStart().TrimEnd()
                              
                                  $LogMessage = "The following filename was provided: `'$($ProvidedFileProperties.FullName)`'`r`n`r`n$($ProvidedFilePropertyOutput)"
                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                  
                                  Write-Output -InputObject $ProvidedFileProperties
                              }
                            Else
                              {
                                  Write-Output "$($ShowDialog.ToString().Trim())"
                                  Throw "An error has occured"
                              }
                              
                            Try
                              {
                                  $LogMessage = "Attempting to restore all minimized windows. Please Wait..."
                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                  $ShellApp.UndoMinimizeALL()
                              }
                            Catch
                              {
                                  $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                  Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                  If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                              }
                        }
                      Catch
                        {
                            $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                            Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                            If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                        }
                    }

              End
                {                                        
                      Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                      Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
                }
        }
#endregion

#region Function Select-Folder
#Select Folder Using Windows Explorer
    Function Select-Folder
        {
            [CmdletBinding(SupportsShouldProcess=$False)]
                Param
                    (     
                        [Parameter(Mandatory=$False)]
                        [String]$Title = "Please select a folder",

                        [Parameter(Mandatory=$False)]
                        [String]$InitialDirectory,

                        [Parameter(Mandatory=$False)]
                        [Switch]$ContinueOnError
                    )
              
            Begin
                {
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
                
            Process
                {
                  Try
                    {
                        $SourceCode = 
                    @"
using System;
using System.Windows.Forms;
using System.Reflection;
namespace FolderSelect
{
	public class FolderSelectDialog
	{
		System.Windows.Forms.OpenFileDialog ofd = null;
		public FolderSelectDialog()
		{
			ofd = new System.Windows.Forms.OpenFileDialog();
			ofd.Filter = "Folders|\n";
			ofd.AddExtension = false;
			ofd.CheckFileExists = false;
			ofd.DereferenceLinks = true;
			ofd.Multiselect = false;
		}
		public string InitialDirectory
		{
			get { return ofd.InitialDirectory; }
			set { ofd.InitialDirectory = value == null || value.Length == 0 ? Environment.CurrentDirectory : value; }
		}
		public string Title
		{
			get { return ofd.Title; }
			set { ofd.Title = value == null ? "Select a folder" : value; }
		}
		public string FileName
		{
			get { return ofd.FileName; }
		}
		public bool ShowDialog()
		{
			return ShowDialog(IntPtr.Zero);
		}
		public bool ShowDialog(IntPtr hWndOwner)
		{
			bool flag = false;

			if (Environment.OSVersion.Version.Major >= 6)
			{
				var r = new Reflector("System.Windows.Forms");
				uint num = 0;
				Type typeIFileDialog = r.GetType("FileDialogNative.IFileDialog");
				object dialog = r.Call(ofd, "CreateVistaDialog");
				r.Call(ofd, "OnBeforeVistaDialog", dialog);
				uint options = (uint)r.CallAs(typeof(System.Windows.Forms.FileDialog), ofd, "GetOptions");
				options |= (uint)r.GetEnum("FileDialogNative.FOS", "FOS_PICKFOLDERS");
				r.CallAs(typeIFileDialog, dialog, "SetOptions", options);
				object pfde = r.New("FileDialog.VistaDialogEvents", ofd);
				object[] parameters = new object[] { pfde, num };
				r.CallAs2(typeIFileDialog, dialog, "Advise", parameters);
				num = (uint)parameters[1];
				try
				{
					int num2 = (int)r.CallAs(typeIFileDialog, dialog, "Show", hWndOwner);
					flag = 0 == num2;
				}
				finally
				{
					r.CallAs(typeIFileDialog, dialog, "Unadvise", num);
					GC.KeepAlive(pfde);
				}
			}
			else
			{
				var fbd = new FolderBrowserDialog();
				fbd.Description = this.Title;
				fbd.SelectedPath = this.InitialDirectory;
				fbd.ShowNewFolderButton = false;
				if (fbd.ShowDialog(new WindowWrapper(hWndOwner)) != DialogResult.OK) return false;
				ofd.FileName = fbd.SelectedPath;
				flag = true;
			}
			return flag;
		}
	}
	public class WindowWrapper : System.Windows.Forms.IWin32Window
	{
		public WindowWrapper(IntPtr handle)
		{
			_hwnd = handle;
		}
		public IntPtr Handle
		{
			get { return _hwnd; }
		}

		private IntPtr _hwnd;
	}
	public class Reflector
	{
		string m_ns;
		Assembly m_asmb;
		public Reflector(string ns)
			: this(ns, ns)
		{ }
		public Reflector(string an, string ns)
		{
			m_ns = ns;
			m_asmb = null;
			foreach (AssemblyName aN in Assembly.GetExecutingAssembly().GetReferencedAssemblies())
			{
				if (aN.FullName.StartsWith(an))
				{
					m_asmb = Assembly.Load(aN);
					break;
				}
			}
		}
		public Type GetType(string typeName)
		{
			Type type = null;
			string[] names = typeName.Split('.');

			if (names.Length > 0)
				type = m_asmb.GetType(m_ns + "." + names[0]);

			for (int i = 1; i < names.Length; ++i) {
				type = type.GetNestedType(names[i], BindingFlags.NonPublic);
			}
			return type;
		}
		public object New(string name, params object[] parameters)
		{
			Type type = GetType(name);
			ConstructorInfo[] ctorInfos = type.GetConstructors();
			foreach (ConstructorInfo ci in ctorInfos) {
				try {
					return ci.Invoke(parameters);
				} catch { }
			}

			return null;
		}
		public object Call(object obj, string func, params object[] parameters)
		{
			return Call2(obj, func, parameters);
		}
		public object Call2(object obj, string func, object[] parameters)
		{
			return CallAs2(obj.GetType(), obj, func, parameters);
		}
		public object CallAs(Type type, object obj, string func, params object[] parameters)
		{
			return CallAs2(type, obj, func, parameters);
		}
		public object CallAs2(Type type, object obj, string func, object[] parameters) {
			MethodInfo methInfo = type.GetMethod(func, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return methInfo.Invoke(obj, parameters);
		}
		public object Get(object obj, string prop)
		{
			return GetAs(obj.GetType(), obj, prop);
		}
		public object GetAs(Type type, object obj, string prop) {
			PropertyInfo propInfo = type.GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return propInfo.GetValue(obj, null);
		}
		public object GetEnum(string typeName, string name) {
			Type type = GetType(typeName);
			FieldInfo fieldInfo = type.GetField(name);
			return fieldInfo.GetValue(null);
		}
	}
}
"@
                        $Assemblies = ('System.Windows.Forms', 'System.Reflection')
                        Add-Type -TypeDefinition $SourceCode -ReferencedAssemblies $Assemblies -ErrorAction Stop
          
                        If ((!($PSBoundParameters.ContainsKey('InitialDirectory'))) -and ([String]::IsNullOrEmpty($InitialDirectory)))
                          {
                            $InitialDirectory = "$($EnvTemp.TrimEnd('\'))"
                          }
              
                        If (!(Test-Path -Path $InitialDirectory)) {New-Folder -Path $InitialDirectory -ContinueOnError:$False -Verbose}
    
                        $FolderSelectionDialog = New-Object 'FolderSelect.FolderSelectDialog'
                        $FolderSelectionDialog.Title = $Title
                        $FolderSelectionDialog.InitialDirectory = $InitialDirectory
                        
                        Try
                          {
                              $LogMessage = "Attempting to minimize all windows. All minimized windows will be restored after the function `'$($CmdletName)`' has completed. Please Wait..."
                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              $ShellApp.MinimizeAll()
                          }
                        Catch
                          {
                              $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                              Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                              If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                          }
                        
                        [Void]$FolderSelectionDialog.ShowDialog()

                        If (!([String]::IsNullOrEmpty($FolderSelectionDialog.FileName)))
                          {
                              $SelectedFolderProperties = [System.IO.DirectoryInfo[]]$FolderSelectionDialog.FileName
                              $SelectedFolderPropertyOutput = ($SelectedFolderProperties | Format-List -Property * | Out-String).TrimStart().TrimEnd()
                              
                              $LogMessage = "The following folder was selected: `'$($SelectedFolderProperties.FullName)`'`r`n`r`n$($SelectedFolderPropertyOutput)"
                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              
                              Write-Output -InputObject $SelectedFolderProperties
                          }
                        Else
                          {
                              Throw "A valid folder was not selected"
                          }
                          
                        Try
                          {
                              $LogMessage = "Attempting to restore all minimized windows. Please Wait..."
                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              $ShellApp.UndoMinimizeALL()
                          }
                        Catch
                          {
                              $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                              Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                              If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                          }
                    }
                  Catch
                    {
                        $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                        Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                        If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                    }
                }
        
            End
              {                                        
                    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
              }                       

        }
#endregion

#region Function Select-File
#Select Files Using Windows Explorer
    Function Select-File
        {
            [CmdletBinding()]
                Param
                    (
                        [Parameter(Mandatory=$False)]
                        [String]$Title = "Please select file(s)",
                        
                        [Parameter(Mandatory=$False)] 
                        [String]$Extension,
                        
                        [Parameter(Mandatory=$False)] 
                        [String]$Filter = "All Files | *.*", 
                        
                        [Parameter(Mandatory=$False)]
                        [String]$InitialDirectory, 
                        
                        [Parameter(Mandatory=$False)]
                        [Switch]$MultiSelect, 
                        
                        [Parameter(Mandatory=$False)]
                        [Switch]$RestoreDirectory, 
                        
                        [Parameter(Mandatory=$False)]
                        [Switch]$ValidateNames,

                        [Parameter(Mandatory=$False)]
                        [Switch]$ContinueOnError 
                    )
                      
            Begin
              {
                  [String]$CmdletName = $MyInvocation.MyCommand.Name 
                  Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                  Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              }
              
            Process
              {
                  If ((!($PSBoundParameters.ContainsKey('InitialDirectory'))) -and ([String]::IsNullOrEmpty($InitialDirectory)))
                    {
                        $InitialDirectory = "$($EnvTemp.TrimEnd('\'))"
                    }
              
                  If (!(Test-Path -Path $InitialDirectory)) {New-Folder -Path $InitialDirectory -ContinueOnError:$False -Verbose}
          
                  [Void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                        
                  $FileBrowserDialog = New-Object System.Windows.Forms.OpenFileDialog
                  $FileBrowserDialog.DefaultExt = $Extension
                  $FileBrowserDialog.Filter = $Filter
                  $FileBrowserDialog.FilterIndex = "0"
                  $FileBrowserDialog.InitialDirectory = $InitialDirectory
                  $FileBrowserDialog.Title = $Title
                        
                  If ($MultiSelect.IsPresent) {$FileBrowserDialog.Multiselect = $True} Else {$FileBrowserDialog.Multiselect = $False}
                  If ($RestoreDirectory.IsPresent) {$FileBrowserDialog.RestoreDirectory = $True} Else {$FileBrowserDialog.RestoreDirectory = $False}
                  If ($ValidateNames.IsPresent) {$FileBrowserDialog.ValidateNames = $True} Else {$FileBrowserDialog.ValidateNames = $False}
                
                  Try
                    {
                        $LogMessage = "Attempting to minimize all windows. All minimized windows will be restored after the function `'$($CmdletName)`' has completed. Please Wait..."
                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                        $ShellApp.MinimizeAll()
                    }
                  Catch
                    {
                        $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                        Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                        If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                    }
                    
                  [Void]$FileBrowserDialog.ShowDialog((New-Object 'System.Windows.Forms.Form' -Property @{TopMost = $True; TopLevel = $True}))

                  If ($FileBrowserDialog.FileNames.Count -gt 0)
                      {
                          ForEach ($File In $FileBrowserDialog.FileNames)
                            {
                                $FileProperties = [System.IO.FileInfo[]]$File
                                $FilePropertyOutput = ($FileProperties | Format-List -Property * | Out-String).TrimStart().TrimEnd()
                                $LogMessage = "The following file was selected: `'$($FileProperties.FullName)`'`r`n`r`n$($FilePropertyOutput)"
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                            }
                            
                          $Results = [System.IO.FileInfo[]]$FileBrowserDialog.FileNames
                          Write-Output -InputObject $Results
                      }
                  Else
                    {
                        Throw "No valid files were selected"
                    }
                    
                  Try
                    {
                        $LogMessage = "Attempting to restore all minimized windows. Please Wait..."
                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                        $ShellApp.UndoMinimizeALL()
                    }
                  Catch
                    {
                        $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                        Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                        If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                    }
              }
                  
            End
              {                                        
                    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
              }
        }
#endregion

#region Function Get-FilteredWinEvents
Function Get-FilteredWinEvents
  {
    [CmdletBinding()]
      Param
        (
            [Parameter(Mandatory=$True, Position = 1)]
            [ValidateRange(([Int32]::MinValue), ([Int32]::MaxValue))]
            [Int32]$EventID = "1074",
            
            [Parameter(Mandatory=$True, Position = 2)]
            [ValidateNotNullOrEmpty()]
            [String]$EventIDDescription,
            
            [Parameter(Mandatory=$False, Position = 2)]
            [ValidateRange(([Long]::MinValue), ([Long]::MaxValue))]
            [Long]$MaxEvents = 5,
            
            [Parameter(Mandatory=$False, Position = 3)]
            [Switch]$ContinueOnError
        )
 
      DynamicParam
        {
            $ParameterName = 'EventLogName'
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
            $ParameterAttribute.Mandatory = $True
            $ParameterAttribute.Position = 0
            $AttributeCollection.Add($ParameterAttribute)
            $arrSet = [System.Diagnostics.EventLog]::GetEventLogs() | Sort-Object | Select-Object -ExpandProperty Log -Unique
            $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
            $AttributeCollection.Add($ValidateSetAttribute)
            $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [String], $AttributeCollection)
            $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
            Write-Output -InputObject $RuntimeParameterDictionary
        }

      Begin
        {
            [String]$CmdletName = $MyInvocation.MyCommand.Name 
            Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
            Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
            $EventLogName = $PsBoundParameters[$ParameterName]
            
            $ErrorActionPreference = 'Continue'

            $LogMessage = "The following parameters and values were provided to the `'$($CmdletName)`' function." 
            Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

            $FunctionProperties = Get-Command -Name $CmdletName
              
            ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
              {
                  If (!([String]::IsNullOrEmpty($Parameter)))
                    {
                        $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                        $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                        If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                          {
                              $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)" 
                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          }
                    }
              }

            $DateTimeLogFormat = 'dddd, MMMM dd, yyyy hh:mm:ss tt'  ###Monday, January 01, 2019 10:15:34 AM###
        }
        
      Process
        {
          Try
            {
                $LogMessage = "Attempting to retrieve the `'$($MaxEvents.ToString())`' most recent events for Event ID `'$($EventID)`' [Description: $($EventIDDescription)] from the `'$($EventLogName)`' event log. Please Wait..."
                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
            
                $Events = Get-WinEvent -FilterHashtable @{LogName="$($EventLogName)"; ID=$($EventID)} -MaxEvents $MaxEvents | Sort-Object -Property TimeCreated
                
                $EventCount = $Events | Measure-Object | Select-Object -ExpandProperty Count
                
                [Int]$EventCounter = 1
                
                $LogMessage = "`'$($EventCount)`' results were returned from the query"
                Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
          
                $ResultantPropertiesFinal = @()
          
                ForEach ($Event In $Events)
                  {
                      $ResultantPropertiesTemporary = New-Object -TypeName 'PSObject'
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "Date" -Value ([DateTime]"$($Event.TimeCreated)")
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "DateAsString" -Value ([String]::New($Event.TimeCreated.ToString($DateTimeLogFormat)))
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "User" -Value ($Event.Properties[6].Value)
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "Process" -Value ($Event.Properties[0].Value) 
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "Action" -Value ($Event.Properties[4].Value) 
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "Reason" -Value ($Event.Properties[2].Value) 
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "ReasonCode" -Value ($Event.Properties[3].Value) 
                      $ResultantPropertiesTemporary | Add-Member -MemberType NoteProperty -Name "Comment" -Value ($Event.Properties[5].Value)
                      
                      [System.Text.StringBuilder]$StringBuilder = [System.Text.StringBuilder]::New()
                                                                          
                      $ResultantPropertiesTemporaryMembers = $ResultantPropertiesTemporary | Get-Member -MemberType Property, NoteProperty
                                                  
                      ForEach ($Member in $ResultantPropertiesTemporaryMembers)
                        {
                            $MemberName = "$($Member.Name)"
                            $MemberValue = ($ResultantPropertiesTemporary.$($Member.Name))
                            $MemberNameAndValue = "`r`n$($MemberName): $($MemberValue)" 
                            [Void]$StringBuilder.Append($MemberNameAndValue)
                        }
                               
                      $StringBuilderResult = [String]::New($StringBuilder.ToString().TrimStart().TrimEnd())

                      $LogMessage = "Event $($EventCounter.ToString()) of $($EventCount.ToString())`r`n`r`n$($StringBuilderResult)`r`n" 
                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Event $($EventCounter.ToString()) of $($EventCount.ToString())" -ContinueOnError:$True

                      $ResultantPropertiesFinal += $ResultantPropertiesTemporary
                      
                      $EventCounter++
                  }
            }
          Catch
            {
                $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
            }

            Write-Output -InputObject ($ResultantPropertiesFinal | Sort-Object -Property Date)
        }
        
      End
        {
            Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
            Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
        }
  }
#endregion

#region Function Mount-RegistryHive
  Function Mount-RegistryHive
    {
        [CmdletBinding(SupportsShouldProcess=$True)]
       
          Param
            (
                [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({(Test-Path -Path $_)})]
                [String]$Path,
                
                [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({($_ -ilike "HKU\*") -or ($_ -ilike "HKLM\*")})]
                [String]$MountPath,
                
                [Parameter(Mandatory=$False)]
                [Switch]$CopyHive
            )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
          }

        Process
          {                   
              Try
                {
                    [System.IO.FileInfo]$PathProperties = $Path
                
                    $RandomGUID = "$([System.GUID]::NewGuid().ToString().ToUpper())"
                
                    If ($CopyHive.IsPresent -eq $True)
                      {
                          $HiveDestination = "$($EnvTemp.TrimEnd('\'))\$($RandomGUID)"
                          If (!(Test-Path -Path $HiveDestination)) {New-Folder -Path $HiveDestination -Verbose -ContinueOnError:$False}
                          Copy-File -Path "$($Path)" -Destination "$($HiveDestination)"
                          $Path = "$($HiveDestination)\$($PathProperties.Name)"
                          [System.IO.FileInfo]$PathProperties = $Path
                      }
                
                    If ((!($PSBoundParameters.ContainsKey('MountPath'))) -and ([String]::IsNullOrEmpty($MountPath)))
                      {
                          $MountPath = "HKLM\$($RandomGUID)"
                      }
                      
                    $LogMessage = "Mount Path: `'$($MountPath)`'"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    $MountPathConverted = Convert-RegistryPath -Key "$($MountPath)"
                    $LogMessage = "Mount Path Converted: `'$($MountPathConverted)`'"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                
                    $LogMessage = "Attempting to mount registry hive `'$($PathProperties.FullName)`' into the following mount path `'$($MountPath)`'. Please Wait..."
                    
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    $MountRegistryHive = Execute-Process -Path "reg.exe" -Parameters "Load `"$($MountPath)`" `"$($PathProperties.FullName)`"" -CreateNoWindow -PassThru -ExitOnProcessFailure:$False -ContinueOnError:$True
                                        
                    If ($MountRegistryHive.ExitCode -iin @('0'))
                      {
                          $LogMessage = "Mounting of registry hive `'$($PathProperties.FullName)`' into the following mount path `'$($MountPath)`' was successful"
                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      }
                    Else
                      {
                          $ErrorMessage = "Failed to mount registry hive `'$($PathProperties.FullName)`' into the following mount path `'$($MountPath)`'"
                          Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          Throw "$($ErrorMessage)"
                      }
                      
                    $ResultantProperties = New-Object -TypeName 'PSObject'
                    $ResultantProperties | Add-Member -Name "ParentPath" -Value "$($PathProperties.Directory)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "Path" -Value "$($PathProperties.FullName)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "FileName" -Value "$($PathProperties.Name)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "MountPath" -Value "$($MountPath)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "MountPathConverted" -Value "$($MountPathConverted)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "GUID" -Value "$($RandomGUID)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "ExitCode" -Value "$($MountRegistryHive.ExitCode)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "StdOut" -Value "$($MountRegistryHive.StdOut)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "StdErr" -Value "$($MountRegistryHive.StdErr)" -MemberType NoteProperty
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True    
                }
                
              Write-Output -InputObject $ResultantProperties
          }
        
        End
          {                                        
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
  #endregion
    
#region Function Dismount-RegistryHive
  Function Dismount-RegistryHive
    {
        [CmdletBinding(SupportsShouldProcess=$True)]
       
          Param
            (        
                [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({($_ -ilike "HKU\*") -or ($_ -ilike "HKLM\*")})]
                [String]$MountPath,
                
                [Parameter(Mandatory=$False)]
                [Switch]$RemoveHive,
                
                [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({(Test-Path -Path $_)})]
                [String]$Path,
                
                [Parameter(Mandatory=$False)]
                [Switch]$Recurse
            )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
          }

        Process
          {           
              Try
                {  
                    $LogMessage = "Mount Path: `'$($MountPath)`'"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    $MountPathConverted = Convert-RegistryPath -Key "$($MountPath)"
                    $LogMessage = "Mount Path Converted: `'$($MountPathConverted)`'"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                
                    $LogMessage = "Attempting to dismount the associated registry hive from the following mount path `'$($MountPath)`'. Please Wait..." 
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                                  
                    [Void][GC]::Collect()
                    
                    [Void][GC]::WaitForPendingFinalizers()
                    
                    $DismountRegistryHive = Execute-Process -Path "reg.exe" -Parameters "Unload `"$($MountPath)`"" -CreateNoWindow -PassThru -ExitOnProcessFailure:$False -ContinueOnError:$True     
                    
                    If ($DismountRegistryHive.ExitCode -iin @('0'))
                      {
                          $LogMessage = "Dismounting of the associated registry hive from the following mount path `'$($MountPath)`' was successful"
                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      }
                    Else
                      {
                          $ErrorMessage = "Failed to dismount registry hive: $($DismountRegistryHive.StdErr)"
                          Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          Throw "$($ErrorMessage)"
                      }
                      
                    If ($RemoveHive.IsPresent -eq $True)
                      {
                          If ((!([String]::IsNullOrEmpty($Path))))
                            {
                                $PathProperties = Get-Item -Path $Path -Force
                            
                                If (($Recurse.IsPresent -eq $True) -and ($PathProperties.GetType().Name -ieq 'DirectoryInfo'))
                                  {
                                      Remove-Folder -Path "$($PathProperties.FullName)" -Verbose -ContinueOnError:$False
                                  }
                                ElseIf (($PathProperties.GetType().Name -ieq 'FileInfo'))
                                  {
                                      Remove-File -Path "$($PathProperties.FullName)" -Verbose -ContinueOnError:$False
                                  }      
                            }
                      }
                      
                    $ResultantProperties = New-Object -TypeName 'PSObject'
                    $ResultantProperties | Add-Member -Name "MountPath" -Value "$($MountPath)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "MountPathConverted" -Value "$($MountPathConverted)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "ExitCode" -Value "$($DismountRegistryHive.ExitCode)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "StdOut" -Value "$($DismountRegistryHive.StdOut)" -MemberType NoteProperty
                    $ResultantProperties | Add-Member -Name "StdErr" -Value "$($DismountRegistryHive.StdErr)" -MemberType NoteProperty 
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True 
                }
                
              Write-Output -InputObject $ResultantProperties
          }
        
        End
          {                                        
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
  #endregion
  
#region Function Uninstall-Application
#Remove software in a more comprehensive way (Leveraging various PSADT functions here)
Function Uninstall-Application
    {
        <#
          .SYNOPSIS
          
          .DESCRIPTION
          
          .PARAMETER
          
          .EXAMPLE
          #Define the product name for software detection/removal
            [Regex]$ProductName = "^(.*Adobe.*Acrobat.*Reader.*)|(.*Google.*Chrome.*)$"
            [Regex]$ProductNameExclusions = "(^.{0,0}$)"
            
          #Processes to close if they are running during deployment
            $ProcessesToClose = "AcroRd32=Adobe Acrobat Reader,Acrobat=Adobe Acrobat,chrome=Google Chrome"

          #Uninstall the applications meeting the specified criteria
            If (!([String]::IsNullOrEmpty($ProductName)))
              {
                  If (!([String]::IsNullOrEmpty($ProcessesToClose)))
                    {
                        Uninstall-Application -ProductName "$($ProductName.ToString())" -ProductNameExclusions "$($ProductNameExclusions.ToString())" -PromptToCloseProcesses -ProcessesToClose $ProcessesToClose -ForceCloseProcesses
                    }
                  Else
                    {
                        Uninstall-Application -ProductName "$($ProductName.ToString())" -ProductNameExclusions "$($ProductNameExclusions.ToString())"
                    }
              }

          .EXAMPLE
          #Define the product name for software detection/removal
            [Regex]$ProductName = "^(.*Adobe.*Acrobat.*Reader.*)|(.*Google.*Chrome.*)$"
            [Regex]$ProductNameExclusions = "(^.{0,0}$)"
            
          #Processes to close if they are running during deployment
            $ProcessesToClose = "AcroRd32=Adobe Acrobat Reader,Acrobat=Adobe Acrobat,chrome=Google Chrome"

          #Uninstall the applications meeting the specified criteria
            If (!([String]::IsNullOrEmpty($ProductName)))
              {
                  If (!([String]::IsNullOrEmpty($ProcessesToClose)))
                    {
                        Uninstall-Application -ProductName "$($ProductName.ToString())" -ProductNameExclusions "$($ProductNameExclusions.ToString())" -AdditionalEXEParameters "YourAdditionalParameters" -PromptToCloseProcesses -ProcessesToClose $ProcessesToClose -ForceCloseProcesses -ShowProgress -Restart
                    }
                  Else
                    {
                        Uninstall-Application -ProductName "$($ProductName.ToString())" -ProductNameExclusions "$($ProductNameExclusions.ToString())" -EXEParameters "YourAdditionalParameters" -ShowProgress -Restart
                    }
              }

          .NOTES
          
          .LINK
        #>
        
          [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = '__DefaultParameterSet')]
       
          Param
            (
                [Parameter(Mandatory=$True)]
                [ValidateNotNullOrEmpty()]
                [Regex]$ProductName,

                [Parameter(Mandatory=$True)]
                [ValidateNotNullOrEmpty()]
                [Regex]$ProductNameExclusions,

                [Parameter(Mandatory=$False)]
                [Switch]$PromptToCloseProcesses,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$ProcessesToClose,
                
                [Parameter(Mandatory=$False)]
                [Switch]$ForceCloseProcesses,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [Int]$ForceCloseProcessTimeout = 120,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$EXEParameters,

                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$MSIParameters,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$AddEXEParameters = "/S",

                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$AddMSIParameters = "REBOOT=REALLYSUPPRESS",
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String[]]$AcceptableExitCodes = @("0", "3010"),
                
                [Parameter(Mandatory=$False)]
                [Switch]$NoEXERemoval,

                [Parameter(Mandatory=$False)]
                [Switch]$NoMSIRemoval,
                
                [Parameter(Mandatory=$False)]
                [Switch]$ShowProgress,

                [Parameter(Mandatory=$False)]
                [Switch]$Restart,
                
                [Parameter(Mandatory=$False)]
                [Switch]$ExitOnProcessFailure,   

                [Parameter(Mandatory=$False)]
                [Switch]$ContinueOnError
            )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              
              $LogMessage = "The following parameters and values were provided" 
              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

              $FunctionProperties = Get-Command -Name $CmdletName
              
              ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
                {
                    If (!([String]::IsNullOrEmpty($Parameter)))
                      {
                          $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                          $ParameterValueCount = $ParameterProperties.Value | Measure-Object | Select-Object -ExpandProperty Count
                          
                          If ($ParameterValueCount -gt 1)
                            {
                                $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join "`r`n"
                                $LogMessage = "$($ParameterProperties.Name):`r`n`r`n$($ParameterValueStringFormat)"
                            }
                          Else
                            {
                                $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)"
                            }
                           
                          If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                            {
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                            }
                      }
                }
          }
          
        Process
          {                   
              Try
                {
                    If (($PromptToCloseProcesses.IsPresent -eq $True) -and (!([String]::IsNullOrEmpty($ProcessesToClose))))
                      {
                          If ($ForceCloseProcesses.IsPresent -eq $True)
                            {
                                Show-InstallationWelcome -MinimizeWindows:$False -TopMost:$True -CloseApps "$($ProcessesToClose)" -PersistPrompt -ForceCloseAppsCountdown $ForceCloseProcessTimeout
                            }
                          Else
                            {
                                Show-InstallationWelcome -MinimizeWindows:$False -TopMost:$True -CloseApps "$($ProcessesToClose)" -PersistPrompt
                            }
                      }

                    $SoftwareDetection = Get-InstalledApplication -Name $ProductName -RegEx | Where-Object {$_.DisplayName -inotmatch "$($ProductNameExclusions.ToString())"}
                    
                    $SoftwareDetectionCount = $SoftwareDetection | Measure-Object | Select-Object -ExpandProperty Count
                    
                    If ($SoftwareDetectionCount -gt 0)
                      {
                          ForEach ($Item In $SoftwareDetection)
                              {
                                  If (!([String]::IsNullOrEmpty($Item.UninstallString)))
                                      {                                            
                                          Write-Log -Message "Now removing `'$($Item.DisplayName) [$($Item.DisplayVersion)]`'. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                          
                                          If ($ShowProgress.IsPresent -eq $True)
                                            {
                                                Show-InstallationProgress -WindowLocation BottomRight -StatusMessage "Now removing`r`n$($Item.DisplayName)`r`n$($Item.DisplayVersion)" -TopMost:$True
                                            }
                                          
                                          If (($Item.UninstallString.StartsWith('"')) -and ($Item.UninstallString -inotlike "*msiexec*") -and ($NoEXERemoval.IsPresent -eq $False))
                                              {
                                                  [String[]]$UninstallStringParts = $Item.UninstallString -Split '"' | Where-Object {(!([String]::IsNullOrEmpty($_)))}
                                                  
                                                  $UninstallCommand = "$($UninstallStringParts[$UninstallStringParts.GetLowerBound(0)].Trim())"
                                                  
                                                  If ($UninstallStringParts.GetUpperBound(0) -gt 0)
                                                    {
                                                        $UninstallParameters = "$($UninstallStringParts[1..$UninstallStringParts.GetUpperBound(0)].Trim() -Join ' ')"
                                                    }
                                                  Else
                                                    {
                                                        $UninstallParameters = $Null
                                                    }
                                            
                                                  If ($PSBoundParameters.ContainsKey('EXEParameters'))
                                                    {
                                                        $UninstallParametersFinal = "$($EXEParameters)"
                                                    }
                                                  ElseIf (!($PSBoundParameters.ContainsKey('EXEParameters')))
                                                    {
                                                        If ($UninstallParameters -ine $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($UninstallParameters) $($AddEXEParameters)"   
                                                          }
                                                        ElseIf ($UninstallParameters -ieq $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($AddEXEParameters)"
                                                          }
                                                    }

                                                  Write-Log -Message "Uninstall Command: $($UninstallCommand)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  Write-Log -Message "Uninstall Parameters: $($UninstallParametersFinal)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  $UninstallApplication = Execute-Process -Path "$($UninstallCommand)" -Parameters "$($UninstallParametersFinal)" -CreateNoWindow -PassThru -Verbose -ExitOnProcessFailure:($ExitOnProcessFailure.IsPresent) -ContinueOnError:($ContinueOnError.IsPresent)
                                              }
                                          ElseIf (!($Item.UninstallString.StartsWith('"')) -and ($Item.UninstallString -inotlike "*msiexec*") -and ($NoEXERemoval.IsPresent -eq $False))
                                              {
                                                  [Regex]$RegularExpression = "(.*\.[A-Za-z0-9]{3,4})"
                                                  
                                                  Write-Log -Message "Splitting original uninstall string with the following regular expression: `'$($RegularExpression.ToString())`'" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  
                                                  [String[]]$UninstallStringParts = $Item.UninstallString -Split $RegularExpression.ToString() | Where-Object {!([String]::IsNullOrEmpty($_))} | ForEach-Object {$_.Trim()}
                                                  
                                                  $UninstallCommand = "$($UninstallStringParts[$UninstallStringParts.GetLowerBound(0)])"  
                                                  
                                                  If ($UninstallStringParts.GetUpperBound(0) -gt 0)
                                                    {
                                                        $UninstallParameters = "$($UninstallStringParts[1..$UninstallStringParts.GetUpperBound(0)] -Join ' ')"
                                                    }
                                                  Else
                                                    {
                                                        $UninstallParameters = $Null
                                                    }    
                                          
                                                  If ($PSBoundParameters.ContainsKey('EXEParameters'))
                                                    {
                                                        $UninstallParametersFinal = "$($EXEParameters)"
                                                    }
                                                  ElseIf (!($PSBoundParameters.ContainsKey('EXEParameters')))
                                                    {
                                                        If ($UninstallParameters -ine $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($UninstallParameters) $($AddEXEParameters)"   
                                                          }
                                                        ElseIf ($UninstallParameters -ieq $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($AddEXEParameters)"
                                                          }
                                                    }

                                                  Write-Log -Message "Uninstall Command: $($UninstallCommand)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  Write-Log -Message "Uninstall Parameters: $($UninstallParametersFinal)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  $UninstallApplication = Execute-Process -Path "$($UninstallCommand)" -Parameters "$($UninstallParametersFinal)" -CreateNoWindow -PassThru -Verbose -ExitOnProcessFailure:($ExitOnProcessFailure.IsPresent) -ContinueOnError:($ContinueOnError.IsPresent)
                                              }
                                          ElseIf (($Item.UninstallString -ilike "msiexec*") -and ([String]::IsNullOrEmpty($Item.ProductCode)) -and ($NoMSIRemoval.IsPresent -eq $False))
                                              {
                                                  [Regex]$RegularExpression = "(.*\.[A-Za-z0-9]{3,4})"
                                                  
                                                  Write-Log -Message "Splitting original uninstall string with the following regular expression: `'$($RegularExpression.ToString())`'" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  
                                                  [String[]]$UninstallStringParts = $Item.UninstallString -Split $RegularExpression.ToString() | Where-Object {!([String]::IsNullOrEmpty($_))} | ForEach-Object {$_.Trim()}
                                                  
                                                  $UninstallCommand = "$($UninstallStringParts[$UninstallStringParts.GetLowerBound(0)])"  
                                                  
                                                  If ($UninstallStringParts.GetUpperBound(0) -gt 0)
                                                    {
                                                        $UninstallParameters = "$($UninstallStringParts[1..$UninstallStringParts.GetUpperBound(0)] -Join ' ')"
                                                    }
                                                  Else
                                                    {
                                                        $UninstallParameters = $Null
                                                    }    
                                          
                                                  If ($PSBoundParameters.ContainsKey('MSIParameters'))
                                                    {
                                                        $UninstallParametersFinal = "$($MSIParameters)"
                                                    }
                                                  ElseIf (!($PSBoundParameters.ContainsKey('MSIParameters')))
                                                    {
                                                        If ($UninstallParameters -ine $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($UninstallParameters) $($AddMSIParameters)"   
                                                          }
                                                        ElseIf ($UninstallParameters -ieq $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($AddMSIParameters)"
                                                          }
                                                    }

                                                  Write-Log -Message "Uninstall Command: $($UninstallCommand)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  Write-Log -Message "Uninstall Parameters: $($UninstallParametersFinal)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                  $UninstallApplication = Execute-Process -Path "$($UninstallCommand)" -Parameters "$($UninstallParametersFinal)" -CreateNoWindow -PassThru -Verbose -ExitOnProcessFailure:($ExitOnProcessFailure.IsPresent) -ContinueOnError:($ContinueOnError.IsPresent)
                                              }
                                          ElseIf (($Item.UninstallString -ilike "msiexec*") -and (!([String]::IsNullOrEmpty($Item.ProductCode))) -and ($NoMSIRemoval.IsPresent -eq $False))
                                              {
                                                  If ($PSBoundParameters.ContainsKey('MSIParameters'))
                                                    {
                                                        $UninstallParametersFinal = "$($MSIParameters)"
                                                        $UninstallApplication = Remove-MSIApplications -Name "$($Item.DisplayName)" -Exact -Parameters "$($UninstallParametersFinal)" -PassThru -Verbose -ContinueOnError:($ContinueOnError.IsPresent)
                                                    }
                                                  ElseIf (!($PSBoundParameters.ContainsKey('MSIParameters')))
                                                    {
                                                        If ($AddMSIParameters -ine $Null)
                                                          {
                                                              $UninstallParametersFinal = "$($AddMSIParameters)"  
                                                              $UninstallApplication = Remove-MSIApplications -Name "$($Item.DisplayName)" -Exact -AddParameters "$($UninstallParametersFinal)" -PassThru -Verbose -ContinueOnError:($ContinueOnError.IsPresent)
                                                          }
                                                        ElseIf ($AddMSIParameters -ieq $Null)
                                                          {
                                                              $UninstallApplication = Remove-MSIApplications -Name "$($Item.DisplayName)" -Exact -PassThru -Verbose -ContinueOnError:($ContinueOnError.IsPresent)
                                                          }
                                                    }
                                              }
                                        
                                          #$UninstallApplication | Get-Member -MemberType NoteProperty | ForEach-Object {If (![String]::IsNullOrEmpty($UninstallApplication.$($_.Name))) {Write-Log -Message "$($_.Name) = $($UninstallApplication.$($_.Name))" -Severity 1 -LogType "CMTrace" -Source "$($CmdletName)" -ContinueOnError:$True}}
                                          
                                          If ($UninstallApplication.ExitCode -iin @($AcceptableExitCodes))
                                            {
                                                $LogMessage = "Removal Successful: $($Item.DisplayName) [$($Item.DisplayVersion)]"
                                                Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                            }
                                          Else
                                            {
                                                $ErrorMessage = "Removal Failed: $($Item.DisplayName) [$($Item.DisplayVersion)]"
                                                Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                            }
                                    
                                          Write-Output -InputObject ($UninstallApplication)
                                      }
                              }
                      }
                    Else
                      {
                          $ProductNames = ($ProductName | ForEach-Object {"`"$($_)`""}) -Join ' or '
                          Write-Log -Message "No applications matching $($ProductNames) need to be removed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      }
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
        
        End
          {                                        
                If ($Restart.IsPresent -eq $True)
                  {
                      Show-InstallationRestartPrompt -NoCountdown
                  }
                
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Get-Shortcut
#Get the properties of both traditional and advertised shortcuts
Function Get-Shortcut
    {
        <#
          .SYNOPSIS
          Retrieves the file information and shortcut properties of one or more shortcut(s)

          .DESCRIPTION
          Retrieves the file information and shortcut properties of one or more shortcut(s)
          
          .PARAMETER FolderPath
          Specifies one or more folder locations containing shortcut files (lnk or url)
          
          .PARAMETER FilePath
          Specifies one or more paths to shortcut files (lnk or url)
          
          .EXAMPLE
          Get-Shortcut
          
          .EXAMPLE
          Get-Shortcut -FolderPath "$([System.Environment]::GetFolderPath('CommonDesktop'))"

          .EXAMPLE
          Get-Shortcut -FolderPath "$([System.Environment]::GetFolderPath('CommonDesktop'))", "$([System.Environment]::GetFolderPath('CommonPrograms'))"
          
          .EXAMPLE
          Get-Shortcut -FilePath "$([System.Environment]::GetFolderPath('CommonPrograms'))\Accessories\Paint.lnk"

          .EXAMPLE
          $Shortcuts = Get-ChildItem -Path "$([System.Environment]::GetFolderPath('CommonPrograms'))" -Include @("*.lnk", "*.url") -Recurse -Force
          Get-Shortcut -FilePath ($Shortcuts.FullName)
        #>
        
        [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = '__DefaultParameterSetName')]
       
        Param
          (               
              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ParameterSetName = '__DefaultParameterSetName')]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({(Test-Path -Path $_) -and (Test-Path -Path $_ -PathType Container)})]
              [String[]]$FolderPath,
              
              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ParameterSetName = 'File')]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({(Test-Path -Path $_) -and (Test-Path -Path $_ -PathType Leaf)})]
              [String[]]$FilePath,
              
              [Parameter(Mandatory=$False, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$False)]
              [ValidateNotNullOrEmpty()]
              [String]$Filter
          )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True   
              
              $ErrorActionPreference = 'Continue'
          }

        Process
          {           
              Try
                {                      
                    [String[]]$IncludedFileTypes = @("*.lnk", "*.url")
                    
                    $oMSI = New-Object -ComObject 'WindowsInstaller.Installer'
                
                    $oShell = New-Object -ComObject 'WScript.Shell'
                    
                    $ResultantPropertiesFinal = @()
                    
                    If ($PSCmdlet.ParameterSetName -ieq '__DefaultParameterSetName')
                      {
                          If ((!($PSBoundParameters.ContainsKey('FolderPath'))) -and ([String]::IsNullOrEmpty($FolderPath)))
                            {
                                [String[]]$FolderPath = "$([System.Environment]::GetFolderPath('Desktop'))", "$([System.Environment]::GetFolderPath('CommonDesktop'))", "$([System.Environment]::GetFolderPath('Programs'))", "$([System.Environment]::GetFolderPath('CommonPrograms'))"
                            }
                            
                          If ($PSBoundParameters.ContainsKey('Filter'))
                            {
                                $Results = Get-ChildItem -Path $FolderPath -Filter $Filter -Include $IncludedFileTypes -Recurse -Force
                            }
                          Else
                            {
                                $Results = Get-ChildItem -Path $FolderPath -Include $IncludedFileTypes -Recurse -Force
                            }
                      }
                    ElseIf ($PSCmdlet.ParameterSetName -ieq 'File')
                      {
                          If ($PSBoundParameters.ContainsKey('Filter'))
                            {
                                $Results = Get-Item -Path $FilePath -Filter $Filter -Include $IncludedFileTypes -Force
                            }
                          Else
                            {
                                $Results = Get-Item -Path $FilePath -Include $IncludedFileTypes -Force
                            }    
                      }
                    
                    ForEach ($Item In $Results)
                      {
                          $LogMessage = "Now processing the following shortcut: `'$($Item.Fullname)`'" 
                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                
                          $ShortcutProperties = $oShell.CreateShortcut($Item.FullName)
													
                          $ResultantPropertiesTemporary = New-Object -TypeName 'PSObject'
                          $ResultantPropertiesTemporary | Add-Member -Name "ShortcutFileInfo" -Value ([System.IO.FileInfo]$Item) -MemberType NoteProperty

                          If ($Item.Extension -ieq '.lnk')
                            {
                                Try
                                  {
                                      $ResultantPropertiesTemporary | Add-Member -Name "TargetPath" -Value ([System.IO.FileInfo]$ShortcutProperties.TargetPath) -MemberType NoteProperty
                                  }
                                Catch
                                  {
                                      $ResultantPropertiesTemporary | Add-Member -Name "TargetPath" -Value $Null -MemberType NoteProperty
                                  }
																
                                $ResultantPropertiesTemporary | Add-Member -Name "ShortcutType" -Value "File" -MemberType NoteProperty
                            }
                          ElseIf ($Item.Extension -ieq '.url')
                            {
                                Try
                                  {
                                      $ResultantPropertiesTemporary | Add-Member -Name "TargetPath" -Value ([System.URI]$ShortcutProperties.TargetPath) -MemberType NoteProperty
                                  }
                                Catch
                                  {
                                      $ResultantPropertiesTemporary | Add-Member -Name "TargetPath" -Value $Null -MemberType NoteProperty
                                  }
																
                                $ResultantPropertiesTemporary | Add-Member -Name "ShortcutType" -Value "URL" -MemberType NoteProperty	
                            }
														
                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "Arguments" -Value "$($ShortcutProperties.Arguments)" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "Arguments" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "Description" -Value "$($ShortcutProperties.Description)" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "Description" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "HotKey" -Value "$($ShortcutProperties.HotKey)" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "HotKey" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "IconIndex" -Value "$($ShortcutProperties.IconLocation.Split(',')[1].Trim())" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "IconIndex" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "IconLocation" -Value "$($ShortcutProperties.IconLocation)" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "IconLocation" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "RelativePath" -Value "$($ShortcutProperties.RelativePath)" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "RelativePath" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "WindowStyle" -Value "$($ShortcutProperties.WindowStyle)" -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "WindowStyle" -Value $Null -MemberType NoteProperty
                            }

                          Try
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "WorkingDirectory" -Value ([System.IO.DirectoryInfo]$ShortcutProperties.WorkingDirectory) -MemberType NoteProperty
                            }
                          Catch
                            {
                                $ResultantPropertiesTemporary | Add-Member -Name "WorkingDirectory" -Value $Null -MemberType NoteProperty
                            }

                          #If the shortcut is an advertisted shortcut, such as those that get created by Microsoft Office or other Windows installer based products, the actual path along with a [System.IO.FileInfo] object properties will be created and added to output object.
                            $ResultantPropertiesTemporary | Add-Member -Name "AdvertistedShortcutFileInfo" -Value $Null -MemberType NoteProperty
														
                            Try
                              {
                                  $oMSIShortcutProperties = $oMSI.ShortcutTarget($Item.FullName)
                                
                                  If ($? -eq $True)
                                    {
                                        [System.IO.FileInfo]$AdvertistedShortcutFileInfo = $oMSI.ComponentPath($oMSIShortcutProperties.StringData(1), $oMSIShortcutProperties.StringData(3))
                                        $ResultantPropertiesTemporary | Add-Member -Name "AdvertistedShortcutFileInfo" -Value ($AdvertistedShortcutFileInfo) -MemberType NoteProperty -Force
                                    }
                              }
                            Catch
                              {
                          
                              }
		
                          $LogMessage = "The following properties were found`r`n`r`n$($ResultantPropertiesTemporary | Format-List -Property * | Out-String)"
                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          
                          $ResultantPropertiesFinal += $ResultantPropertiesTemporary
                      }
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True 
                }
                				
              Write-Output -InputObject $ResultantPropertiesFinal		
          }
        
        End
          {                                        
              Try
                {
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($oMSI) | Out-Null
                }
                Catch
                {
                    Write-Log -Message "Failed to release the following COM Object `'oMSI`'.`r`n`r`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                }
                                                         
              Try
                {
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($oShell) | Out-Null
                }
              Catch
                {
                    Write-Log -Message "Failed to release the following COM Object `'oShell`'.`r`n`r`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                }
        
              Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Get-FileAttributes
Function Get-FileAttributes
    {
        <#
          .DESCRIPTION
          Returns a powershell object to the pipeline with the file attributes of one or more files
          .PARAMETER Path
          A valid path to any file on the file system
          .EXAMPLE
          [System.IO.FileInfo[]]$File = "C:\YourFolder\YourFile.msp"
          $Results = Get-FileAttributes -Path "$($File.FullName)"
          Write-Output -InputObject $Results
        #>
        
        [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = '__DefaultParameterSetName')]
       
        Param
          (        
              [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({(Test-Path -Path $_ -IsValid) -and (Test-Path -Path $_ -PathType Leaf)})]
              [Alias('FullName')]
              [String[]]$Path,
              
              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError         
          )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              
              $ErrorActionPreference = 'Stop'
              
              $LogMessage = "The following parameters and values were provided" 
              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

              $FunctionProperties = Get-Command -Name $CmdletName
              
              ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
                {
                    If (!([String]::IsNullOrEmpty($Parameter)))
                      {
                          $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                          $ParameterValueCount = $ParameterProperties.Value | Measure-Object | Select-Object -ExpandProperty Count
                          
                          If ($ParameterValueCount -gt 1)
                            {
                                $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join "`r`n"
                                $LogMessage = "$($ParameterProperties.Name):`r`n`r`n$($ParameterValueStringFormat)"
                            }
                          Else
                            {
                                $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)"
                            }
                           
                          If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                            {
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                            }
                      }
                }
          }

        Process
          {           
              Try
                {                      
                    $oShell = New-Object -ComObject 'Shell.Application'
                    $TextInfo = (Get-Culture).TextInfo
                
                    $ResultantPropertiesFinal = @()
                    
                    ForEach ($Item In $Path)
                      {
                          [System.IO.FileInfo]$FileProperties = "$($Item)"

                          If ($FileProperties.Exists -eq $True)
                            {              
                                $LogMessage = "Now retrieving populated atttributes for the following file: `'$($FileProperties.FullName)`'. Please Wait..." 
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                        
                                $oFolder = $oShell.Namespace($FileProperties.Directory.FullName)
                                $oFile = $oFolder.ParseName($FileProperties.Name)
                                
                                $ResultantPropertiesTemporary = New-Object -TypeName 'PSObject'

                                For ($AttributeCounter = 0; $AttributeCounter -le 500; $AttributeCounter++)
                                  {
                                      $AttributeValue = $oFolder.GetDetailsOf($oFile, $AttributeCounter)
                                                                
                                      If ((!([String]::IsNullOrEmpty($AttributeValue))))
                                        {
                                            #File attribute values commonly contain whitespace at the beginning or end and need to be trimmed so that the powershell pipeline object gets output correctly
                                              $AttributeValue = $AttributeValue.ToString().Trim()
                                        
                                            #Determine the name of the attribute
                                              $AttributeName = $oFolder.GetDetailsOf($Null, $AttributeCounter)
                                            
                                            If (!([String]::IsNullOrEmpty($AttributeName)))
                                              {
                                                  #Make the attribute name lower case
                                                    $AttributeName = ($AttributeName | Out-String).Replace("`n", '').ToLowerInvariant()
                                                  
                                                  #Capitalize the first letter of each word within the 'AttributeName' for standardization and neatness and trim the leading and trailing white space for the powershell pipeline object
                                                    $AttributeName = $TextInfo.ToTitleCase($AttributeName).Replace(' ','').Trim()
                                                    
                                                  #Transform the specified attributes into richer objects if necessary
                                                    If (($AttributeName -ieq "FolderPath") -and (Test-Path -Path $AttributeValue -IsValid)) {$AttributeValue = [System.IO.DirectoryInfo]"$($AttributeValue)"}
                                                    If (($AttributeName -ieq "Path") -and (Test-Path -Path $AttributeValue -IsValid)) {$AttributeValue = [System.IO.FileInfo]"$($AttributeValue)"}
                                                    If (($AttributeName -ieq "ContentCreated") -and ([Boolean]($AttributeValue -as [DateTime]))) {$AttributeValue = [DateTime]::Parse($AttributeValue)}
                                                    If (($AttributeName -ieq "DateAccessed") -and ([Boolean]($AttributeValue -as [DateTime]))) {$AttributeValue = [DateTime]::Parse($AttributeValue)}
                                                    If (($AttributeName -ieq "DateCreated") -and ([Boolean]($AttributeValue -as [DateTime]))) {$AttributeValue = [DateTime]::Parse($AttributeValue)}
                                                    If (($AttributeName -ieq "DateModified") -and ([Boolean]($AttributeValue -as [DateTime]))) {$AttributeValue = [DateTime]::Parse($AttributeValue)}
                                                    If (($AttributeName -ieq "DateLastSaved") -and ([Boolean]($AttributeValue -as [DateTime]))) {$AttributeValue = [DateTime]::Parse($AttributeValue)}
                                                  
                                                  #Add each property to the powershell object
                                                    $ResultantPropertiesTemporary | Add-Member -Name ($AttributeName) -Value ($AttributeValue) -MemberType NoteProperty
                                              }
                                        }
                                  }
                                  
                              #Log file properties to the application log
                                $LogMessage = "The following attributes were found`r`n`r`n$(($ResultantPropertiesTemporary | Format-List -Property * | Out-String).TrimStart().TrimEnd())`r`n`r`n" 
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True  
                            
                              #Write the powershell object to the powershell pipeline
                                  Write-Output -InputObject $ResultantPropertiesTemporary
                                
                                $ResultantPropertiesFinal += $ResultantPropertiesTemporary  
                            }
                      }
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }  
          }
        
        End
          {                                        
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Copy-File2
Function Copy-File2 {
  <#
      .SYNOPSIS
      Copy a file or group of files to a destination path.
      .DESCRIPTION
      Copy a file or group of files to a destination path.
      .PARAMETER Path
      Path of the file to copy.
      .PARAMETER Destination
      Destination Path of the file to copy.
      .PARAMETER Recurse
      Copy files in subdirectories.
      .PARAMETER ContinueOnError
      Continue if an error is encountered. This will continue the deployment script, but will not continue copying files if an error is encountered. Default is: $true.
      .PARAMETER ContinueFileCopyOnError
      Continue copying files if an error is encountered. This will continue the deployment script and will warn about files that failed to be copied. Default is: $false.
      .EXAMPLE
      Copy-File -Path "$dirSupportFiles\MyApp.ini" -Destination "$envWindir\MyApp.ini"
      .EXAMPLE
      Copy-File -Path "$dirSupportFiles\*.*" -Destination "$envTemp\tempfiles"
      Copy all of the files in a folder to a destination folder.
      .NOTES
      .LINK
      http://psappdeploytoolkit.com
  #>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [string[]]$Path,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [string]$Destination,
    [Parameter(Mandatory=$false)]
    [switch]$Recurse = $false,
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [boolean]$ContinueOnError = $true,
    [ValidateNotNullOrEmpty()]
    [boolean]$ContinueFileCopyOnError = $false,
    [Parameter(Mandatory=$false)]
    [switch]$PassThru = $false,
    [Parameter(Mandatory=$false)]
    [switch]$LogCopiedFiles = $false
  )
	
  Begin {
    ## Get the name of this function and write header
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
  }
  Process {
    Try {
            $Results = @()

      $null = $fileCopyError
      If ((-not ([IO.Path]::HasExtension($Destination))) -and (-not (Test-Path -LiteralPath $Destination -PathType 'Container'))) {
        Write-Log -Message "Destination folder does not exist, creating destination folder [$destination]." -Source ${CmdletName}
        $null = New-Item -Path $Destination -Type 'Directory' -Force -ErrorAction 'Stop'
      }
			
      $null = $FileCopyError
      If ($Recurse) {
        Write-Log -Message "Copy file(s) recursively in path [$path] to destination [$destination]." -Source ${CmdletName}
        If (-not $ContinueFileCopyOnError) {
          $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop' -PassThru:$($PassThru.IsPresent) -OutVariable Result
        }
        Else {
          $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable FileCopyError -PassThru:$($PassThru.IsPresent) -OutVariable Result
        }
      }
      Else {
        Write-Log -Message "Copy file in path [$path] to destination [$destination]." -Source ${CmdletName}
        If (-not $ContinueFileCopyOnError) {
          $null = Copy-Item -Path $Path -Destination $Destination -Force -ErrorAction 'Stop' -PassThru:$($PassThru.IsPresent) -OutVariable Result
        }
        Else {
          $null = Copy-Item -Path $Path -Destination $Destination -Force -ErrorAction 'SilentlyContinue' -ErrorVariable FileCopyError -PassThru:$($PassThru.IsPresent) -OutVariable Result
        }
      }

      If ($fileCopyError) { 
        Write-Log -Message "The following warnings were detected while copying file(s) in path [$path] to destination [$destination]. `n$FileCopyError" -Severity 2 -Source ${CmdletName}
      }
      Else {
        Write-Log -Message "File copy completed successfully." -Source ${CmdletName}            
      }
    }
    Catch {
      Write-Log -Message "Failed to copy file(s) in path [$path] to destination [$destination]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
      If (-not $ContinueOnError) {
        Throw "Failed to copy file(s) in path [$path] to destination [$destination]: $($_.Exception.Message)"
      }
    }

    If ($PassThru.IsPresent -eq $True)
      {
          $Results += $Result
          Write-Output -InputObject $Results

          If ($LogCopiedFiles.IsPresent -eq $True)
            {
                $ResultsLogFormat = ($Results | Sort-Object -Property FullName | Format-List -Property FullName, @{Name="LastWriteTime";Expression={$_.LastWriteTime.ToString($DateTimeLogFormat)}} | Out-String).TrimStart().TrimEnd()

                [System.Text.StringBuilder]$StringBuilder = [System.Text.StringBuilder]::New()

                [Void]$StringBuilder.Append("`r`n")
                [Void]$StringBuilder.Append("The following files were copied")
                [Void]$StringBuilder.Append("`r`n`r`n")
                [Void]$StringBuilder.Append($ResultsLogFormat)
 
                $LogMessage = "$($StringBuilder.ToString().TrimStart().TrimEnd())"
                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
            }
      }
  }
  End {
    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True 
    Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
  }
}
#endregion

#region Function Show-WPFWindow
#Show the XAML WPF Object on the screen
    Function Show-WPFWindow
        {
            Param
                (
                    [Parameter(Mandatory=$True)]
                    [Windows.Window]$Window
                )

            Begin
                {
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }

            Process
                {
                    $Result = $Null
                    $Null = $Window.Dispatcher.InvokeAsync{($Result = $Window.ShowDialog()); (Set-Variable -Name Result -Value $Result -Scope 1)}.Wait()
                    Return $Result
                }
            
            End
              {                                        
                    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
              }
        }
#endregion

#region Function Export-FormattedSpreadsheet
Function Export-FormattedSpreadsheet
    {
        <#
          .SYNOPSIS
          Exports one or more powershell objects to a formatted excel spreadsheet.
          
          .DESCRIPTION
          Exports one or more powershell objects to a formatted excel spreadsheet. Each object will be added to a separate worksheet with the same spreadsheet.
          
          .PARAMETER InputObject
          An array of hashtables containing the following required properties (WorksheetName, TableName, TableStyle, Object, IncludedProperties, ExcludedProperties, SortProperties, Descending)

          .PARAMETER Path
          The full path to the spreadsheet that will be created. Must have a .xlsx file extension.

          .PARAMETER DefaultColumnWidth
          The default column width for the entire workbook. Default value is 60.

          .PARAMETER FreezeTopRow
          Freezes the top row so that your column headers do not disappear when scrolling.

          .PARAMETER FreezeFirstColumn
          Freezes the first column so that the values do not disappear when scrolling.

          .PARAMETER FreezeTopRowFirstColumn
          Freezes the first column and the first column so that headers and first column data do not disappear when scrolling.

          .PARAMETER AutoSize
          Autosizes the columns in order that all data can be clearly seen.

          .PARAMETER WrapText
          Allows the text within cells to be wrapped. This is useful if you have long values contained in a cell.

          .PARAMETER ContinueOnError
          Ignore any terminating errors and continue with function execution.
          
          .EXAMPLE
          [HashTable[]]$Objects = @(
                            @{
                                WorksheetName = "Processes";
                                TableName = "Processes";
                                TableStyle = "Medium2";
                                Object = (Get-Process -IncludeUserName | Get-Random -Count 5);
                                IncludedProperties = ('ID', 'Name', 'Path', 'FileVersion', 'StartTime', 'Handle');
                                ExcludedProperties = ($Null);
                                SortProperties = ('Name');
                                Descending = $True;
                            },
                            
                            @{
                                WorksheetName = "Services";
                                TableName = "Services";
                                TableStyle = "Light19";
                                Object = (Get-Service | Get-Random -Count 5);
                                IncludedProperties = ('*');
                                ExcludedProperties = ($Null);
                                SortProperties = ('Name');
                                Descending = $False;
                            }
                        )
                        
          [System.IO.FileInfo]$ExportPath = "$($Env:Userprofile)\Desktop\Reports\FormattedSpreadsheet.xlsx"

          Export-FormattedSpreadsheet -InputObject ($Objects) -Path "$($ExportPath.FullName)" -FreezeTopRowFirstColumn -WrapText -ContinueOnError:$True
          
          .LINK
          https://psappdeploytoolkit.com/

          .LINK
          https://www.powershellgallery.com/packages/ImportExcel
        #>
                
        [CmdletBinding(ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByInputObject', HelpURI = '', SupportsPaging = $True, SupportsShouldProcess = $True, PositionalBinding = $True)]
       
        Param
          (        
              [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [HashTable[]]$InputObject,
                
              [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({(Test-Path -Path $_.FullName -IsValid) -and ($_.Extension -imatch "^\.(xlsx)")})]
              [System.IO.FileInfo]$Path,

              [Parameter(Mandatory=$False)]
              [Int]$DefaultColumnWidth,

              [Parameter(Mandatory=$False)]
              [Switch]$FreezeTopRow,

              [Parameter(Mandatory=$False)]
              [Switch]$FreezeFirstColumn,    
              
              [Parameter(Mandatory=$False)]
              [Switch]$FreezeTopRowFirstColumn,

              [Parameter(Mandatory=$False)]
              [Switch]$AutoSize,
              
              [Parameter(Mandatory=$False)]
              [Switch]$WrapText,
                            
              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError
          )
                    
        Begin
          {
              Try
                {
                    #Determine the date and time we executed the function
                      $FunctionStartTime = (Get-Date)
                    
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True   
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                      
                    $LogMessage = "The following parameters and values were provided to the `'$($CmdletName)`' function." 
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Get-FunctionParameters" -ContinueOnError:$True

                    $FunctionProperties = Get-Command -Name $CmdletName
                    
                    $FunctionParameters = $FunctionProperties.Parameters.Keys
              
                    ForEach ($Parameter In $FunctionParameters)
                      {
                          If (!([String]::IsNullOrEmpty($Parameter)))
                            {
                                $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                                $ParameterValueCount = $ParameterProperties.Value | Measure-Object | Select-Object -ExpandProperty Count
                          
                                If ($ParameterValueCount -gt 1)
                                  {
                                      $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join "`r`n"
                                      $LogMessage = "$($ParameterProperties.Name):`r`n`r`n$($ParameterValueStringFormat)"
                                  }
                                Else
                                  {
                                      $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                      $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)"
                                  }
                           
                                If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                                  {
                                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Get-FunctionParameters" -ContinueOnError:$True
                                  }
                            }
                      }

                    $LogMessage = "Function execution began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-Begin" -ContinueOnError:$True
                      
                    [System.Collections.ArrayList]$RequiredModules = @(@{Name = "ImportExcel"; RequiredVersion = "6.5.3"})
                    Receive-Module -Modules  ($RequiredModules) -PackageProviders @("NuGet")
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }

        Process
          {           
              Try
                {  
                    $LogMessage = "Attempting to create and open an excel package object and hold it in memory. Please Wait..." 
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Open-ExcelPackage" -ContinueOnError:$True
                    
                    #Ensure that the excel package is null
                      $ExcelPackage = $Null
                    
                    #Create the excel package and hold it in memory until we close and finalize it
                      $ExcelPackage = Open-ExcelPackage -Path "$($Path.FullName)" -Create -Verbose
                    
                    #Determine the valid table styles and formulate them into a regular expression
                      [Regex]$ValidTableStyles = ([OfficeOpenXml.Table.TableStyles]::GetNames([OfficeOpenXml.Table.TableStyles]) | Sort-Object) -Join "|"
                                
                    #$LogMessage = "See the valid table styles below`r`n`r`n$($ValidTableStyles.ToString().Replace('|',"`r`n"))" 
                    #Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    ForEach ($Item In $InputObject)
                      {
                          If (($Item.ContainsKey('WorksheetName')) -and ($Item.ContainsKey('TableName')) -and ($Item.ContainsKey('Object')) -and ($Item.ContainsKey('IncludedProperties')) -and ($Item.ContainsKey('ExcludedProperties')) -and ($Item.ContainsKey('SortProperties')) -and ($Item.ContainsKey('TableStyle')) -and ($Item.ContainsKey('Descending')))
                            {
                                #Table names cannot start with numbers so a 3 digit non numeric string will be used instead to avoid potential errors.
                                  $RandomString = (-Join ((65..90) + (97..122) | Get-Random -Count 3 | ForEach-Object {[Char]$_})).ToString().ToUpperInvariant()
                            
                                #Structure the properties from the current hashtable being processed so that they can be passed the Export-Excel function
                                  [String]$WorksheetName = "$($Item.WorksheetName)"
                                  [String]$TableName = "$($RandomString)_$($Item.TableName)"
                                  
                                  $LogMessage = "Now adding worksheet `"$($WorksheetName)`" to the excel package. Please Wait..." 
                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Add-Worksheet" -ContinueOnError:$True

                                  #Use a default table style if the specified table style is not contained within the list of available table styles.
                                    If ($Item.TableStyle -imatch $ValidTableStyles.ToString())
                                      {
                                          [String]$TableStyle = "$($Item.TableStyle)"
                                      }
                                    Else
                                      {
                                          [String]$TableStyle = "Medium2"
                                      }
                                  
                                  [Object]$Object = ($Item.Object)
                                  [Object]$IncludedProperties = ($Item.IncludedProperties)
                                  [Object]$ExcludedProperties = ($Item.ExcludedProperties)
                                  [Object]$SortProperties = ($Item.SortProperties)
                                  [Boolean]$Descending = ($Item.Descending)
                            
                                #Get the final result set that will be exported to the spreadsheet
                                  $FormattedResults = $Object | Sort-Object -Property ($SortProperties) -Descending:($Descending) | Select-Object -Property ($IncludedProperties) -ExcludeProperty ($ExcludedProperties)
                                                                
                                #If the final result set contains data, then add the result set to the spreadsheet
                                  If ($FormattedResults -ine $Null)
                                    {
                                        #Create the excel spreadsheet
                                          $CreateWorksheet = $FormattedResults | Export-Excel -ExcelPackage ($ExcelPackage) -WorksheetName "$($WorksheetName)" -TableName "$($TableName)" -TableStyle "$($TableStyle)" -ReturnRange -AutoNameRange -ClearSheet -PassThru -Verbose
                                      
                                        #Bind to the created worksheet
                                          $Worksheet = $ExcelPackage.Workbook.Worksheets["$($WorksheetName)"]

                                        #Set the default column width
                                          If (($PSBoundParameters.ContainsKey('DefaultColumnWidth') -eq $True) -and (($DefaultColumnWidth -ine $Null) -or ($DefaultColumnWidth -ine '')))
                                            {
                                                Try
                                                  {
                                                      $LogMessage = "Attempting to set the default column width to $($DefaultColumnWidth.ToString()). Please Wait..." 
                                                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Set-DefaultColWidth" -ContinueOnError:$True
                                                      $Worksheet.DefaultColWidth = $DefaultColumnWidth
                                                  }
                                                Catch
                                                  {
                                                      $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                                      Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "Error-$($CmdletName)" -ContinueOnError:$True
                                                  }
                                            }

                                        #Optionally freeze the first row, first column, or both
                                          If (($FreezeTopRowFirstColumn.IsPresent -eq $True) -or (($FreezeTopRow.IsPresent -eq $True) -and ($FreezeFirstColumn.IsPresent -eq $True)))
                                            {
                                                $LogMessage = "Attempting to freeze the top row and the first column. Please Wait..." 
                                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "FreezeTopRowFirstColumn" -ContinueOnError:$True
                                                $Worksheet.View.FreezePanes(2, 2)
                                            }
                                          ElseIf ($FreezeTopRow.IsPresent -eq $True)
                                            {
                                                $LogMessage = "Attempting to freeze the top row. Please Wait..." 
                                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "FreezeTopRow" -ContinueOnError:$True
                                                $Worksheet.View.FreezePanes(2, 1)
                                            }
                                          ElseIf ($FreezeFirstColumn.IsPresent -eq $True)
                                            {
                                                $LogMessage = "Attempting to freeze the first column. Please Wait..." 
                                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "FreezeFirstColumn" -ContinueOnError:$True
                                                $Worksheet.View.FreezePanes(1, 2)
                                            }
                                                                
                                        #Determine the first and last cell header address
                                          $Headers_RangeStart = $Worksheet.Dimension.Start.Address
                                          $Headers_RangeEnd = "$($Worksheet.Dimension.End.Address -ireplace "\d+$", '')1"
  
                                        #Concatenate the first and last cell header address into a cell range
                                          $Headers_TargetRange = "$($Headers_RangeStart):$($Headers_RangeEnd)"

                                        #Format the cell header range with the specified option(s)
                                          $LogMessage = "Attempting to set formatting for the header cells `"$($Headers_TargetRange)`". Please Wait..." 
                                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Set-ExcelRange" -ContinueOnError:$True
                                          
                                          Set-ExcelRange -Range "$($Headers_TargetRange)" -WorkSheet ($Worksheet) -Underline -UnderLineType Single -HorizontalAlignment Center -VerticalAlignment Center -Bold:$True -FontSize 16 -Verbose
                                                
                                        #Determine the first and last cell non-header address
                                          $NonHeaders_RangeStart = "$($Worksheet.Dimension.Start.Address -ireplace "\d+$", '')2"
                                          $NonHeaders_RangeEnd = $Worksheet.Dimension.End.Address
  
                                        #Concatenate the first and last cell non-header address into a cell range
                                          $NonHeaders_TargetRange = "$($NonHeaders_RangeStart):$($NonHeaders_RangeEnd)"
        
                                        #Format the cell non-header range with the specified option(s)
                                          $LogMessage = "Attempting to set formatting for the non header cells `"$($NonHeaders_TargetRange)`". Please Wait..." 
                                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Set-ExcelRange" -ContinueOnError:$True
                                          
                                          Set-ExcelRange -Range "$($NonHeaders_TargetRange)" -WorkSheet ($Worksheet) -HorizontalAlignment Center -VerticalAlignment Top -Bold:$False -FontSize 12 -AutoSize:$($AutoSize.IsPresent) -WrapText:$($WrapText.IsPresent) -Verbose
                                          
                                        #Autosize the non header cell range(s)
                                          $LogMessage = "Attempting to auto size all non header cells `"$($NonHeaders_TargetRange)`". Please Wait..." 
                                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Set-ExcelRange" -ContinueOnError:$True
                                          
                                          $WorksheetDimensions = "$($Worksheet.Dimension.Start.Address):$($Worksheet.Dimension.End.Address)"
                                          
                                          Set-ExcelRange -Range "$($WorksheetDimensions)" -WorkSheet ($Worksheet) -AutoSize:$($AutoSize.IsPresent) -Verbose                                        
                                    }
                                  Else
                                    {                                      
                                        $LogMessage = "The `"$($Item.WorksheetName)`" object does not contain any results after formatting and will not be added to the spreadsheet" 
                                        Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "Empty-Worksheet" -ContinueOnError:$True
                                    } 
                            }
                          Else
                            {
                                $LogMessage = "The `"$($Item.WorksheetName)`" hashtable does not contain the required properties and will not be added to the spreadsheet." 
                                Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "Invalid-HashTable" -ContinueOnError:$True
                            }
                      }
                      
                    #Flush the excel package to the spreadsheet on the file system and close the excel package out of memory
                      $LogMessage = "Attempting to export the excel spreadsheet to the following path `"$($Path.FullName)`". Please Wait..." 
                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Close-ExcelPackage" -ContinueOnError:$True
                      
                      If ($Path.Directory.Exists -eq $False) {New-Folder -Path "$($Path.Directory.FullName)" -Verbose -ContinueOnError:$False}
                    
                      Close-ExcelPackage -ExcelPackage ($ExcelPackage) -Verbose
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "Error-$($CmdletName)" -ContinueOnError:$True
                    
                    Close-ExcelPackage -ExcelPackage ($ExcelPackage) -NoSave
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
        
        End
          {                                        
              #Determine the date and time the function completed execution
                $FunctionEndTime = (Get-Date)

                $LogMessage = "Function execution ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-End" -ContinueOnError:$True

              #Log the total script execution time  
                $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                $LogMessage = "Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-Total" -ContinueOnError:$True

              Try
                {
                    Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "Error-$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
    }
#endregion

#region Function Execute-MSIPatchSequence
    Function Execute-MSIPatchSequence
    {
        <#
          .SYNOPSIS
          Leverages the PSADT, and the MSI powershell module, in order to programatically determine which .msp files apply to a given .msi file within one or more directories and installs them in the appropriate order.
					
          .DESCRIPTION
          Supplied paths must be directories containing .msi and .msp files
					
          .PARAMETER PackagePath
          One or more directories containing one or more .msi and/or .msp files
					
          .PARAMETER PackageFilter
          One or more file extensions to process
					
          .PARAMETER FilterScript
          Allows for the filtering of .msi files or .msp files based on their table properties
					
          .PARAMETER ProductFilter
          Allows for the filtering of MSI's based on their product name property within the property table
					
          .PARAMETER AdditionalMSIParameters
          Any additional MSI properties that need to be set during installation

          .PARAMETER Recurse
          If specified, recurses through the directorie(s) provided within the PackagePath argument. If this argument is not specified, only the specified folder will be searched.

          .PARAMETER PassThru
          If specified, returns an object to the powershell pipeline containing all MSI files and their respective patches
          
          .EXAMPLE
          [String[]]$Paths = @("C:\Directory1", "C:\Directory2")
          Execute-MSIPatchSequence -PackagePath $Paths -PassThru

          .EXAMPLE
          $OperatingSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_OperatingSystem" -Property * | Select-Object -Property *
          $OSPlatform = "$($OperatingSystem.OSArchitecture -ireplace '(-.+)', '')"
          [String[]]$Paths = @("C:\Directory1", "C:\Directory2")
          [Regex]$ProductFilter = "(.*Ivanti.*Deployment.*Agent.*CCA.*)"
          [ScriptBlock]$FilterScript = {($_.AppSense_Platform -ilike "*$($OSPlatform)*")}
          $AdditionalMSIParameters = "WEB_SITE=`"http://yourserver.youdomain.com:yourport/`""
          Execute-MSIPatchSequence -PackagePath $Paths -ProductFilter $ProductFilter -FilterScript $FilterScript -AdditionalMSIParameters $AdditionalMSIParamters -PassThru
        #>
        
        [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = 'ByFolder')]
       
        Param
          (    
              [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({($ItemProperties = Get-Item -Path $_); ($ItemProperties.Attributes -ieq 'Directory') -and ($ItemProperties.Exists -eq $True)})]
              [String[]]$PackagePath,

              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [String[]]$PackageFilter = @('*.msi', '*.msp'),

              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [ScriptBlock]$FilterScript = {(!([String]::IsNullOrEmpty($_.FullName)))},
							
              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [Regex]$ProductFilter = "(.*)",

              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [String]$AdditionalMSIParameters,

              [Parameter(Mandatory=$False)]
              [Switch]$Recurse,
              
              [Parameter(Mandatory=$False)]
              [Switch]$PassThru,

              [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [String[]]$AcceptableExitCodes = @('0', '3010'),

              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError
          )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              
              $ErrorActionPreference = 'SilentlyContinue'

              $LogMessage = "The following parameters and values were provided" 
              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

              If ($Recurse.IsPresent -eq $False) {$PackagePath = $PackagePath | ForEach-Object {If ($_ -inotmatch '^.+[\\][\*]$') {"$($_)\*"}}}

              $FunctionProperties = Get-Command -Name $CmdletName
              
              ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
                {
                    If (!([String]::IsNullOrEmpty($Parameter)))
                      {
                          $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                          $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                          If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                            {
                                $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)" 
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                            }
                      }
                }

              [Int]$MSICounter = 1
          }

        Process
          {           
              Try
                {  			
                    $RequiredModules = @('MSI')

                    Receive-Module -Name $RequiredModules
										                    
                    $Packages = Get-ChildItem -Path $PackagePath -Recurse:($Recurse.IsPresent) -File -Include $PackageFilter -Force
	
                    $MSIs = $Packages | Where-Object {$_.Extension -ieq ".msi"} | Get-MSIProperty -PassThru | Where-Object -FilterScript $FilterScript | Where-Object -FilterScript {$_.ProductName -imatch $ProductFilter} | Sort-Object -Property ProductName
    
                    $MSICount = $MSIs | Measure-Object | Select-Object -ExpandProperty Count

                    $MSPs = $Packages | Where-Object {$_.Extension -ieq ".msp"} | Get-MSIProperty -PassThru | Where-Object -FilterScript $FilterScript | Where-Object -FilterScript {$_.TargetProductName -imatch $ProductFilter} | Sort-Object -Property TargetProductName
                
                    $MSPCount = $MSPs | Measure-Object | Select-Object -ExpandProperty Count
										
                    If ($PassThru.IsPresent -eq $True)
                      {
                          $ResultantPropertiesFinal = @()
                      }

                    ForEach ($MSI In $MSIs)
                        {  
                            [System.IO.FileInfo]$MSIProperties = "$($MSI.FullName)"
                            
                            $LogMessage = "Attempting to install the following MSI `'$($MSI.FullName)`'. Please Wait..." 
                            Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                            If (!([String]::IsNullOrEmpty($MSI.ManufacturerName)))
                              {
                                  $LogMessage = "[Product $($MSICounter.ToString()) of $($MSICount)] - $($MSI.ProductName) | $($MSI.ManufacturerName)"
                              }
                            Else
                              {
                                  $LogMessage = "[Product $($MSICounter.ToString()) of $($MSICount)] - $($MSI.ProductName)"
                              }
                            
                            Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                            $LogMessage = "Attempting to locate the newest transform located within `'$($MSIProperties.Directory.FullName)`'. Please Wait..." 
                            Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                            
                            $Transform = Get-ChildItem -Path "$($MSIProperties.Directory.FullName)" -File -Filter "*.mst" -Force | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 -Property *
                            $TransformCount = $Transform | Measure-Object | Select-Object -ExpandProperty Count

                            $LogMessage = "`'$($TransformCount)`' transform(s) were found." 
                            Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                            If (!([String]::IsNullOrEmpty($AdditionalMSIParameters)))
                              {
                                  If ($TransformCount -gt 0)
                                    {
                                        $MSIExecutionResult = Execute-MSI -Action Install -Path "$($MSI.FullName)" -Transform "$($Transform.FullName)" -AddParameters "$($AdditionalMSIParameters)" -ContinueOnError:($ContinueOnError.IsPresent) -PassThru -ExitOnProcessFailure:($ContinueOnError.IsPresent)
                                    }
                                  Else
                                    {
                                        $MSIExecutionResult = Execute-MSI -Action Install -Path "$($MSI.FullName)" -AddParameters "$($AdditionalMSIParameters)" -ContinueOnError:($ContinueOnError.IsPresent) -PassThru -ExitOnProcessFailure:($ContinueOnError.IsPresent)
                                    }
                              }
                            Else
                              {
                                  If ($TransformCount -gt 0)
                                    {
                                        $MSIExecutionResult = Execute-MSI -Action Install -Path "$($MSI.FullName)" -Transform "$($Transform.FullName)" -ContinueOnError:($ContinueOnError.IsPresent) -PassThru -ExitOnProcessFailure:($ContinueOnError.IsPresent)
                                    }
                                  Else
                                    {
                                        $MSIExecutionResult = Execute-MSI -Action Install -Path "$($MSI.FullName)" -ContinueOnError:($ContinueOnError.IsPresent) -PassThru -ExitOnProcessFailure:($ContinueOnError.IsPresent)
                                    }
                              }
   
                            $MSI | Add-Member -Name "ExecutionResult" -Value ($MSIExecutionResult) -MemberType NoteProperty
                            
                            $LogMessage = "The following properties were found`r`n`r`n$(($MSI | Format-List -Property * | Out-String).TrimStart().TrimEnd())"
                            Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                            If ($PassThru.IsPresent -eq $True)
                              {
                                  $ResultantPropertiesTemporary = New-Object -TypeName 'PSObject'
                                  $ResultantPropertiesTemporary | Add-Member -Name "MSIProperties" -Value ($MSI) -MemberType NoteProperty   
                              }

                            If ($MSIExecutionResult.ExitCode -inotin $AcceptableExitCodes)
                              {
                                  If ($ContinueOnError.IsPresent -eq $False) {Throw "The following unacceptable Error Code was returned: $($MSIExecutionResult.ExitCode)"}
                              }

                            If ($MSPCount -gt 0)
                              {
                                  $LogMessage = "Determining patch sequence. Please Wait..." 
                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                  $MSIPatchSequence = Get-MSIPatchSequence -Path ($MSPs.FullName) -PackagePath ($MSI.FullName) | Sort-Object -Property Sequence
                
                                  $MSIPatchSequenceCount = $MSIPatchSequence | Measure-Object | Select-Object -ExpandProperty Count
                
                                  If ($MSIPatchSequenceCount -gt 0)
                                      {
                                          $RequiredPatchPropertiesFinal = @()
															
                                          ForEach ($Patch In $MSIPatchSequence)
                                              { 
                                                  $PatchSequenceNumber = $Patch.Sequence + 1
                                                  $MSPProperties = $MSPs | Where-Object {$_.FullName -ieq "$($Patch.Patch)"}
                                            
                                                  $LogMessage = "`'$($MSIPatchSequenceCount.ToString())`' required patches were found." 
                                                  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                                  $LogMessage = "Attempting to install the following patch `'$($MSPProperties.FullName)`'. Please Wait..." 
                                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                                  If (!([String]::IsNullOrEmpty($MSPProperties.ManufacturerName)))
                                                    {
                                                        $LogMessage = "[Patch: $($PatchSequenceNumber) of $($MSIPatchSequenceCount)] - $($MSPProperties.DisplayName) | $($MSPProperties.ManufacturerName)"
                                                    }
                                                  Else
                                                    {
                                                        $LogMessage = "[Patch: $($PatchSequenceNumber) of $($MSIPatchSequenceCount)] - $($MSPProperties.DisplayName)"
                                                    }

                                                  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                                  $LogMessage = "The following properties were found`r`n`r`n$(($MSPProperties | Format-List -Property * | Out-String).TrimStart().TrimEnd())" 
                                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                                  $MSPExecutionResult = Execute-MSI -Action Patch -Path "$($MSPProperties.FullName)" -ContinueOnError:($ContinueOnError.IsPresent) -PassThru -ExitOnProcessFailure:($ContinueOnError.IsPresent)

                                                  $MSPProperties | Add-Member -Name "ExecutionResult" -Value ($MSPExecutionResult) -MemberType NoteProperty

                                                  If ($PassThru.IsPresent -eq $True)
                                                    {
                                                        $RequiredPatchPropertiesTemporary = New-Object -TypeName 'PSObject'
                                                        $RequiredPatchPropertiesTemporary | Add-Member -Name "MSPProperties" -Value ($MSPProperties) -MemberType NoteProperty
                                                        $RequiredPatchPropertiesTemporary | Add-Member -Name "SequenceNumber" -Value ($PatchSequenceNumber) -MemberType NoteProperty
                                                        $RequiredPatchPropertiesFinal += $RequiredPatchPropertiesTemporary
                                                    }

                                                  If ($MSPExecutionResult.ExitCode -inotin $AcceptableExitCodes)
                                                    {
                                                        If ($ContinueOnError.IsPresent -eq $False) {Throw "The following unacceptable Error Code was returned: $($MSPExecutionResult.ExitCode)"}
                                                    }
                                              }
                                      }
                                  Else
                                      {
                                          $LogMessage = "`'$($MSIPatchSequenceCount.ToString())`' required patches were found." 
                                          Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                      }
                              }
                            Else
                              {
                                  $MSIPatchSequenceCount = $MSPCount
                                  
                                  $LogMessage = "`'$($MSIPatchSequenceCount.ToString())`' required patches were found." 
                                  Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              }

                                  If ($PassThru.IsPresent -eq $True)
                                    {
                                        $ResultantPropertiesTemporary | Add-Member -Name "RequiredPatchCount" -Value ($MSIPatchSequenceCount) -MemberType NoteProperty
                                        $ResultantPropertiesTemporary | Add-Member -Name "RequiredPatches" -Value ($RequiredPatchPropertiesFinal) -MemberType NoteProperty
                                        $ResultantPropertiesFinal += $ResultantPropertiesTemporary
                                    }

                                  $MSICounter++
                              }

                    If ($PassThru.IsPresent -eq $True)
                      {
                          Write-Output -InputObject $ResultantPropertiesFinal
                      }
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
        
        End
          {                                        
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Set-ConsoleTitle
Function Set-ConsoleTitle
    {
        <#
          .SYNOPSIS
          Allows settings the console title for the current powershell process.
          
          .DESCRIPTION
          This helps when showing balloon notification(s), as well as the Action Center. So as opposed to everything saying "Windows Powershell". It can say "Your Company" for example.
          
          .PARAMETER ParameterName
          Your parameter description

          .PARAMETER ParameterName
          Your parameter description

          .PARAMETER ParameterName
          Your parameter description
          
          .EXAMPLE
          Place some code here to show how to use your function

          .EXAMPLE
          Place some code here to show how to use your function
  
          .NOTES
          Any useful tidbits
          
          .LINK
          Place any useful link here where your function or cmdlet can be referenced
        #>
        
        [CmdletBinding(ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByInputObject', HelpURI = '', SupportsPaging = $True, SupportsShouldProcess = $True, PositionalBinding = $True)]
       
        Param
          (        
              [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
              [ValidateNotNullOrEmpty()]
              [String]$ConsoleTitle,
                              
              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError        
          )
                    
        Begin
          {
              Try
                {
                    $DateTimeLogFormat = 'dddd, MMMM dd, yyyy hh:mm:ss tt'  ###Monday, January 01, 2019 10:15:34 AM###
                    [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
                    $DateTimeFileFormat = 'yyyyMMdd_hhmmsstt'  ###20190403_115354AM###
                    [ScriptBlock]$GetDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
                    [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
                    $TextInfo = (Get-Culture).TextInfo
                    
                    #Determine the date and time we executed the function
                      $FunctionStartTime = (Get-Date)
                    
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    
                    $LogMessage = "Function `'$($CmdletName)`' is beginning. Please Wait..."
                    Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True  
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                      
                    $LogMessage = "The following parameters and values were provided to the `'$($CmdletName)`' function." 
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                    $FunctionProperties = Get-Command -Name $CmdletName
                    
                    $FunctionParameters = $FunctionProperties.Parameters.Keys
              
                    ForEach ($Parameter In $FunctionParameters)
                      {
                          If (!([String]::IsNullOrEmpty($Parameter)))
                            {
                                $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                                $ParameterValueCount = $ParameterProperties.Value | Measure-Object | Select-Object -ExpandProperty Count
                          
                                If ($ParameterValueCount -gt 1)
                                  {
                                      $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join "`r`n"
                                      $LogMessage = "$($ParameterProperties.Name):`r`n`r`n$($ParameterValueStringFormat)"
                                  }
                                Else
                                  {
                                      $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                      $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)"
                                  }
                           
                                If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                                  {
                                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Get-FunctionParameters" -ContinueOnError:$True
                                  }
                            }
                      }

                    $LogMessage = "Execution of $($CmdletName) began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-Begin" -ContinueOnError:$True
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }

        Process
          {           
              Try
                {  
                    $LogMessage = "Attempting to set the console title for process ID `"$($PID)`" to `"$($ConsoleTitle)`". Please Wait..." 
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                
                    $Host.UI.RawUI.WindowTitle = "$($ConsoleTitle)"
                }
              Catch
                {
                    If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message -Join "`r`n`r`n")"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                    $ErrorMessage = "[Error Message: $($ExceptionMessage)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
        
        End
          {                                        
              Try
                {
                    #Determine the date and time the function completed execution
                      $FunctionEndTime = (Get-Date)

                      $LogMessage = "Execution of $($CmdletName) ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-End" -ContinueOnError:$True

                    #Log the total script execution time  
                      $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                      $LogMessage = "Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-Total" -ContinueOnError:$True
                    
                    $LogMessage = "Function `'$($CmdletName)`' is completed."
                    Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
                }
              Catch
                {
                    If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message -Join "`r`n`r`n")"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                    $ErrorMessage = "[Error Message: $($ExceptionMessage)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
    }
#endregion

#region Function Download-File
Function Download-File
  {
      [CmdletBinding()]
          Param
              (     
                  [Parameter(Mandatory=$False, ValueFromPipeline=$True)]
                  [ValidateNotNullOrEmpty()]
                  [ValidatePattern("^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$")]
                  [String[]]$URL,
                  
                  [Parameter(Mandatory=$False, ValueFromPipeline=$False)]
                  [ValidateNotNullOrEmpty()]
                  [ValidateScript({Test-Path -Path "$($_)" -IsValid})]
                  [System.IO.DirectoryInfo]$Destination,
                  
                  [Parameter(Mandatory=$False, ValueFromPipeline=$False)]
                  [ValidateNotNullOrEmpty()]
                  [Timespan]$Timeout = $(New-TimeSpan -Seconds 15),
                  
                  [Parameter(Mandatory=$False, ValueFromPipeline=$False)]
                  [Switch]$SetOriginalTimestamp,

                  [Parameter(Mandatory=$False, ValueFromPipeline=$False)]
                  [Switch]$PassThru,
                  
                  [Parameter(Mandatory=$False, ValueFromPipeline=$False)]
                  [Switch]$ContinueOnError 
              )
              
      Begin
        {
            Try
              {
                  #Determine the date and time we executed the function
                      $FunctionStartTime = (Get-Date)
                  
                  [String]$CmdletName = $MyInvocation.MyCommand.Name 
                  Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                  Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                  
                  If ((!($PSBoundParameters.ContainsKey('Destination'))) -and ([String]::IsNullOrEmpty($Destination)))
                    {
                        [System.IO.DirectoryInfo]$Destination = "$($Env:Temp.TrimEnd('\'))"
                    }  
              
                  #Define Default Action Preferences
                    $ErrorActionPreference = 'Stop'
                      
                  $LogMessage = "The following parameters and values were provided to the `'$($CmdletName)`' function." 
                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                  $FunctionProperties = Get-Command -Name $CmdletName
              
                  ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
                    {
                        If (!([String]::IsNullOrEmpty($Parameter)))
                          {
                              $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                              $ParameterValueCount = $ParameterProperties.Value | Measure-Object | Select-Object -ExpandProperty Count
                          
                              If ($ParameterValueCount -gt 1)
                                {
                                    $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join "`r`n"
                                    $LogMessage = "$($ParameterProperties.Name):`r`n`r`n$($ParameterValueStringFormat)"
                                }
                              Else
                                {
                                    $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                    $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)"
                                }
                           
                              If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                                {
                                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "Get-FunctionParameters" -ContinueOnError:$True
                                }
                          }
                    }

                  $LogMessage = "Function execution began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-Begin" -ContinueOnError:$True
              }
            Catch
              {
                  $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                  Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                  If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
              }
        }
        
      Process
        {
            $URLCounter = 1

            $URLCount = $URL | Measure-Object | Select-Object -ExpandProperty Count

            Write-Log -Message "Total URL(s) to be downloaded: $($URLCount)" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
            
            If ($PassThru.IsPresent -eq $True)
              {
                  $ResultantPropertiesFinal = @()
              }
            
            ForEach ($Item In $URL)
              {  
                  Try
                    {  
                        If ($PassThru.IsPresent -eq $True)
                          {
                              $ResultantPropertiesNested = @()
                          }
                    
                        [System.URI]$URLProperties = [System.URI]::New($Item)
                        
                        $URLProperties_FileName = [System.IO.Path]::GetFileName($URLProperties.OriginalString)

                        If ($Destination.FullName -inotmatch "^.*\..{1,}$")
                          {
                              [System.IO.FileInfo]$DestinationProperties = [System.IO.FileInfo]::New("$($Destination)\$($URLProperties_FileName)")
                              If ($DestinationProperties.Directory.Exists -eq $False) {New-Folder -Path "$($DestinationProperties.Directory.FullName)" -Verbose -ContinueOnError:$False}
                          }
                        ElseIf ($Destination.FullName -imatch "^.*\..{1,}$")
                          {
                              [System.IO.DirectoryInfo]$DestinationProperties = [System.IO.DirectoryInfo]::New($Destination)
                              If ($DestinationProperties.Exists -eq $False) {New-Folder -Path "$($DestinationProperties.FullName)" -Verbose -ContinueOnError:$False}
                          }

                        $LogMessage = "Attempting to download URL [$($URLCounter.ToString()) of $($URLCount)]. Please Wait...`r`n`r`n[URL: $($URLProperties.OriginalString)]`r`n`r`n[Destination: $($DestinationProperties.FullName)]"
                        Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                        $URLHeaders = Invoke-WebRequest -Uri "$($URLProperties.OriginalString)" -Method Head -TimeoutSec $Timeout.TotalSeconds -UseBasicParsing

                        $ContentLength = $URLHeaders.Headers.'Content-Length'
                        
                        $URL_DownloadSize = $ContentLength / 1MB
                    
                        If ($URL_DownloadSize -ine $Null)
                          {
                              $URL_DownloadSizeRounded = [System.Math]::Round($URL_DownloadSize, 2)
                              $LogMessage = "$($URLProperties_FileName) | Download Size: $($URL_DownloadSizeRounded) MegaBytes"
                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                          }
                          
                        #Download the requested file
                          $WebClient = [System.Net.WebClient]::New()
                          $WebClient.UseDefaultCredentials = $True
                          $WebClient.DownloadFile("$($URLProperties.OriginalString)", "$($DestinationProperties.FullName)")
                          
                        If ($? -eq $True)
                            {
                                Start-Sleep -Seconds 2
                                
                                $LogMessage = "Download of URL `'$($URLProperties_FileName)`' was successful"
                                Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                        
                                If (Test-Path -Path "$($DestinationProperties.FullName)" -PathType Leaf)
                                  {
                                      $DestinationFileInfo = Get-Item -Path "$($DestinationProperties.FullName)" -Force
                                                  
                                      If ($SetOriginalTimestamp.IsPresent -eq $True)
                                        {
                                            If (!([String]::IsNullOrEmpty($URLHeaders.Headers.'Last-Modified')))
                                              {
                                                  $OriginalTimestamp = [DateTime]"$($URLHeaders.Headers.'Last-Modified')"
                                    
                                                  If ($DestinationFileInfo.LastWriteTime -ne $OriginalTimestamp)
                                                    {
                                                        $DateTimeStringFormat = 'dddd, MMMM dd, yyyy hh:mm:ss tt'  ###Monday, January 01, 2019 10:15:34 AM###
                                                        $LogMessage = "Attempting to change the current timestamp of `'$($DestinationFileInfo.FullName)`' from `'$($DestinationProperties.LastWriteTime.ToString($DateTimeStringFormat))`' to the original timestamp of `'$($OriginalTimestamp.ToString($DateTimeStringFormat))`'. Please Wait..."
                                                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                        $DestinationFileInfo.LastWriteTime = $OriginalTimestamp
                                                    }
                                              }
                                        }
                                  }
                                  
                                If ($PassThru.IsPresent -eq $True)
                                  {
                                      $ResultantPropertiesTemporary = New-Object -TypeName 'PSObject'
                                      $ResultantPropertiesTemporary | Add-Member -Name "FileInfo" -Value ($DestinationFileInfo) -MemberType NoteProperty
                                      $ResultantPropertiesTemporary | Add-Member -Name "URLInfo" -Value ($URLProperties) -MemberType NoteProperty
                                      $ResultantPropertiesNested += $ResultantPropertiesTemporary
                                      $ResultantPropertiesFinal += $ResultantPropertiesNested
                                                          
                                      $ResultantPropertiesTemporaryMembers = $ResultantPropertiesTemporary | Get-Member -MemberType Property, NoteProperty | Sort-Object -Property Name
                                                
                                      ForEach ($Member in $ResultantPropertiesTemporaryMembers)
                                        {                                            
                                            $ResultantPropertiesNestedProperties = $ResultantPropertiesTemporary.$($Member.Name)
                                              
                                            $ResultantPropertiesNestedMembers = $ResultantPropertiesNestedProperties | Get-Member -MemberType Property, NoteProperty | Sort-Object -Property Name

                                            #Create a string builder object and add all properties and values from the specified powershell object to the log
                                              [System.Text.StringBuilder]$StringBuilder = [System.Text.StringBuilder]::New()
                          
                                              [Void]$StringBuilder.Append("The following properties are defined within the following object member: $($Member.Name)")
                                                
                                              [Void]$StringBuilder.Append("`r`n`r`n")
                                          
                                              ForEach ($NestedMember In $ResultantPropertiesNestedMembers)
                                                {
                                                    $NestedMemberName = "$($NestedMember.Name)"
                                                    $NestedMemberValue = "$($ResultantPropertiesTemporary.$($Member.Name).$($NestedMember.Name))"
                                                    $NestedMemberNameAndValue = "`r`n$($NestedMemberName): $($NestedMemberValue)" 
                                                    [Void]$StringBuilder.Append($NestedMemberNameAndValue)
                                                }
                                                
                                              $StringBuilderResult = [String]::New($StringBuilder.ToString().TrimStart().TrimEnd())
                                                                     
                                              $LogMessage = "$($StringBuilderResult)" 
                                              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                        }

                                      Write-Output -InputObject ($ResultantPropertiesFinal)
                                      
                                      $LogMessage = "Download [$($URLCounter.ToString()) of $($URLCount)] is completed."
                                      Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                  }
                            }
                    }
                  Catch
                    {
                        $ErrorMessage = "$($CmdletName): $($_.Exception.InnerException)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                        Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                        $WebClient = $Null
                        
                        If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                    }
                    
                  $URLCounter++
                  
                  $Item = $Null

                  $WebClient = $Null
              }
        }
                  
      End
        { 
            #Determine the date and time the function completed execution
              $FunctionEndTime = (Get-Date)

              $LogMessage = "Function execution ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-End" -ContinueOnError:$True

            #Log the total script execution time  
              $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

              $LogMessage = "Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
              Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "ExecutionTime-Total" -ContinueOnError:$True
            
            Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
            Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer                         
        }
  }
#endregion

#region Function Start-ProcessAsCurrentUser
Function Start-ProcessAsCurrentUser
  {
      <#
          .SYNOPSIS
           Uses the Windows API to determine the current console session, retrieve a token for that session, and then start the specified process or script with that token.
          .DESCRIPTION
           This function will be extremely useful when deploying scripts from a management system (ie SCCM) that launches a process as the SYSTEM account. Whilst having your administrative rights, you may need to launch a process as the console user without knowing their password.
           You will then be able to launch processes as that user, and in most cases, provide the user with a better experience during your application deployment
          .PARAMETER
          .EXAMPLE
           Start-ProcessAsCurrentUser -ScriptBlock {$Services = Get-Service | Out-File -FilePath "$($Env:Temp)\Services.txt"; Start-Sleep -Seconds 2; Start-Process -FilePath "notepad.exe" -ArgumentList "$($Env:Temp)\Services.txt"} -Wait
          .EXAMPLE
           Start-ProcessAsCurrentUser -FilePath "$([Environment]::SystemDirectory)\cmd.exe" -ArgumentList "/k" -Visible
          .EXAMPLE
           Start-ProcessAsCurrentUser -Script "C:\testing\test.ps1" -ScriptArguments "-TestMode `"1`""
          .NOTES
          This function must be called from a process with the appropriate permissions. By default, the "NTAuthority\SYSTEM" account has the permission to do so. Otherwise, error handling is built in to avoid errors and inform you
          .LINK
          http://rzander.azurewebsites.net/create-a-process-as-loggedon-user/
      #>
      [CmdletBinding(DefaultParameterSetName = '__DefaultParameterSet')]
        Param
          (
            [Parameter(Mandatory = $False)]
            [ValidateNotNullOrEmpty()]
            [ValidateScript({(Test-Path -Path $_.FullName)})]
            [System.IO.FileInfo]$FilePath = "$([Environment]::SystemDirectory)\WindowsPowershell\v1.0\powershell.exe",
            
            [Parameter(Mandatory = $False)]
            [ValidateNotNullOrEmpty()]
            [String]$ArgumentList,
            
            [Parameter(Mandatory = $False)]
            [ValidateNotNullOrEmpty()]
            [System.IO.DirectoryInfo]$WorkingDirectory = "$($FilePath.Directory.FullName)",
            
            [Parameter(Mandatory = $False)]
            [Switch]$Visible = $False,
            
            [Parameter(Mandatory = $False)]
            [Switch]$Wait = $False,
            
            [Parameter(Mandatory = $False)]
            [ValidateRange(1,([Int]::MaxValue))]
            [Int]$Timeout = 900,
            
            [Parameter(Mandatory = $False, ParameterSetName = 'Script')]
            [ValidateNotNullOrEmpty()]
            [ValidateScript({Test-Path -Path $_})]
            [String]$Script,
            
            [Parameter(Mandatory = $False, ParameterSetName = 'Script')]
            [ValidateNotNullOrEmpty()]
            [String]$ScriptArguments,
            
            [Parameter(Mandatory = $False, ParameterSetName = 'ScriptBlock')]
            [ValidateNotNullOrEmpty()]
            [ScriptBlock]$ScriptBlock
          )
          
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

              If (([Regex]::Escape($FilePath.FullName) -imatch ".*powershell\.exe") -or ([Regex]::Escape($FilePath.FullName) -imatch ".*pwsh\.exe"))
                {
                    If(([String]::IsNullOrEmpty($ArgumentList)) -and (!($PSBoundParameters.ContainsKey('ArgumentList'))))
                      {
                          $ArgumentList = "-NoLogo -NoProfile"
                      }
                
                    If (($PSBoundParameters.ContainsKey('Script')) -and ($PSCmdlet.ParameterSetName -ieq 'Script'))
                      {
                          If ([String]::IsNullOrEmpty($ScriptArguments))
                            {
                                $ArgumentList = "$($ArgumentList) -Script `"$($Script)`""
                            }
                          Else
                            {
                                $ArgumentList = "$($ArgumentList) -Script `"$($Script)`" $($ScriptArguments)"
                            }
                      }
                    ElseIf (($PSBoundParameters.ContainsKey('ScriptBlock')) -and ($PSCmdlet.ParameterSetName -ieq 'ScriptBlock'))
                      {
                          $ScriptBlockBase64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ScriptBlock.ToString().Trim()))
                          $ArgumentList = "$($ArgumentList) -EncodedCommand $($ScriptBlockBase64)"
                      }
                }
          }

        Process
          {
              $Source = @"
using System;  
using System.Runtime.InteropServices;

namespace murrayju.ProcessExtensions  
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
            return true;
        }
    }
}


"@

        If ($SessionZero -eq $True)
          {
              Try
                {  
                    $FormattedArgumentList = (Get-Command -Name $MyInvocation.InvocationName).Parameters.Keys | ForEach-Object `
                      {
                          $ArgumentProperties = Get-Variable -Name $_ -ErrorAction SilentlyContinue
                          
                          If ($ArgumentProperties -ine $Null)
                            {
                                "$($ArgumentProperties.Name): `'$($ArgumentProperties.Value)`'"
                            }
                            
                      } | Out-String
                    
                    $LogMessage = "Attempting to start the specified process as the following user `'$($CurrentLoggedOnUserSession.NTAccount)`'`r`n`r`n$($FormattedArgumentList)"
                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $Source -Language CSharp -ErrorAction Stop
                    $Result = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser("$($FilePath.FullName)", "$($ArgumentList)", "$($WorkingDirectory.FullName)", $Visible.IsPresent)
                    
                    If ($Wait.IsPresent -eq $True)
                      {
                          $ProcessName = "$($FilePath.BaseName)"
                          
                          $ProcessProperties = (Get-Process -Name $ProcessName -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -ieq "$($CurrentLoggedOnUserSession.NTAccount)"} | Sort-Object -Property StartTime -Descending | Select-Object -First 1 -Property *)
                          
                          If ($ProcessProperties -ine $Null)
                            {
                                Try
                                  {
                                      $LogMessage = "Waiting a maximum of `'$($Timeout)`' seconds for the following process to exit`r`n`r`n$($ProcessProperties | Format-List -Property * | Out-String)"
                                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                      Wait-Process -Id $ProcessProperties.ID -Timeout $Timeout
                                  }
                                Catch
                                  {
                                      $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                      Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                  }
                            }
                      }                       
 
                    Write-Output -InputObject $Result
                }
              Catch
                {        
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    Throw "$($ErrorMessage)"
                }
          }
        ElseIf ($SessionZero -eq $False)
          {
              $LogMessage = "The account `'$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`' does not have the appropriate rights to launch an impersonated process."
              Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
          }
      }

      End
        {
            Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
            Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
        }
  }
#endregion

#region Function Get-InstalledSoftware
<#
    .SYNOPSIS
      Get-InstalledSoftware retrieves a list of installed software
    .DESCRIPTION
      Get-InstalledSoftware opens up the specified (remote) registry and scours it for installed software. When found it returns a list of the software and it's version.
    .PARAMETER ComputerName
      The computer from which you want to get a list of installed software. Defaults to the local host.
    .EXAMPLE
      Get-InstalledSoftware DC1
	
      This will return a list of software from DC1. Like:
      Name			Version		Computer  UninstallCommand
      ----			-------     --------  ----------------
      7-Zip 			9.20.00.0	DC1       MsiExec.exe /I{23170F69-40C1-2702-0920-000001000000}
      Google Chrome	65.119.95	DC1       MsiExec.exe /X{6B50D4E7-A873-3102-A1F9-CD5B17976208}
      Opera			12.16		DC1		  "C:\Program Files (x86)\Opera\Opera.exe" /uninstall
    .EXAMPLE
      Import-Module ActiveDirectory
      Get-ADComputer -filter 'name -like "DC*"' | Get-InstalledSoftware
	
      This will get a list of installed software on every AD computer that matches the AD filter (So all computers with names starting with DC)
    .INPUTS
      [string[]]Computername
    .OUTPUTS
      PSObject with properties: Name,Version,Computer,UninstallCommand
    .NOTES
      Author: Anthony Howell
	
      To add directories, add to the LMkeys (LocalMachine)
    .LINK
      [Microsoft.Win32.RegistryHive]
      [Microsoft.Win32.RegistryKey]
    #>
    Function Get-InstalledSoftware
        {
          Param
              (
                  [Alias('LocalMachineType')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 1)]
                  [Microsoft.Win32.RegistryHive]$LMType = ([Microsoft.Win32.RegistryHive]::LocalMachine),

                  [Alias('LocalMachineKeys')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 2)]
                  [String[]]$LMKeys = @("Software\Microsoft\Windows\CurrentVersion\Uninstall", "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),

                  [Alias('CurrentUserType')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 3)]
                  [Microsoft.Win32.RegistryHive]$CUType = ([Microsoft.Win32.RegistryHive]::CurrentUser),

                  [Alias('CurrentUserKeys')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 4)]
                  [String[]]$CUKeys = @("Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                
                  [Alias('InclusionExpression')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 5)]
                  [Regex]$Include = "(.*)",

                  [Alias('ExclusionExpression')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 6)]
                  [Regex]$Exclude = "(^.{0,0}$)",

                  [Alias('REO')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 7)]
                  [Text.RegularExpressions.RegexOptions[]]$RegexOptions = @([Text.RegularExpressions.RegexOptions]::IgnoreCase),
                
                  [Alias('HostName')]
                  [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Position = 8)]
                  [String[]]$ComputerName = @("$($Env:ComputerName)"),
                  
                  [Alias('DL')]
                  [Parameter(ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False, Position = 9)]
                  [Switch]$DisableFunctionLogging = $True
              )
          
          Begin
              {
                  [String]$CmdletName = "$($MyInvocation.MyCommand.Name)" 
                  Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                  Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                  
                  $ErrorActionPreference = 'Continue'

                  $LogMessage = "The following parameters and values were provided" 
                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                  $FunctionProperties = Get-Command -Name $CmdletName
              
                  ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
                    {
                        If (!([String]::IsNullOrEmpty($Parameter)))
                          {
                              $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                              $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                              
                              If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                                {
                                    $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)" 
                                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                }
                          }
                    }
               
                  $IncludeWithOptions = [Regex]::New($Include, $RegexOptions)
                  $ExcludeWithOptions = [Regex]::New($Exclude, $RegexOptions)            		
              }
          
          Process
              {
                  ForEach ($Computer In $ComputerName)
                      {
                          Try
                            {
                                $LogMessage = "Attempting to connect to the following computer: `'$($Computer)`'. Please Wait..." 
                                Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                If ($DisableFunctionLogging.IsPresent -eq $True)
                                  {
                                      $DisableLogging = $True
                                  } 
                                
                                $MasterKeys = @()
                              
                                If (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction Stop)
                                  {
                                      $CURegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($CUtype, $Computer)
                                      $LMRegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($LMtype, $Computer)
			                
                                      ForEach ($Key In $LMkeys)
                                        { 
                                            $RegKey = $LMRegKey.OpenSubkey($Key)
                                            
                                            If ($RegKey -ne $Null)
                                              {
                                                  ForEach ($SubName In $RegKey.GetSubKeyNames())
                                                      {
                                                          ForEach ($Sub In $RegKey.OpenSubKey($SubName))
                                                              {
                                                                  $DisplayName = $Sub.GetValue("DisplayName")

                                                                  If (($DisplayName -imatch $IncludeWithOptions) -and ($DisplayName -inotmatch $ExcludeWithOptions))
                                                                    {      
                                                                        $LogMessage = "Now adding properties for the following software: `'$($DisplayName)`'. Please Wait..." 
                                                                        Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                                                                        $RegistryKeyProperties = New-Object -TypeName 'PSObject'
                                                                        $RegistryKeyProperties | Add-Member -Name "ComputerName" -Value ($Computer) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Path" -Value ($Sub.ToString()) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Name" -Value ($DisplayName) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "SystemComponent" -Value ($Sub.GetValue("SystemComponent")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "ParentKeyName" -Value ($Sub.GetValue("ParentKeyName")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Version" -Value ($Sub.GetValue("DisplayVersion")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "UninstallString" -Value ($Sub.GetValue("UninstallString")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "InstallLocation" -Value ($Sub.GetValue("InstallLocation")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "InstallSource" -Value ($Sub.GetValue("InstallSource")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "DisplayIcon" -Value ($Sub.GetValue("DisplayIcon")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Type" -Value "LocalMachine" -MemberType NoteProperty

                                                                        $LogMessage = "The following properties were found`r`n`r`n$(($RegistryKeyProperties | Format-List -Property * | Out-String).TrimStart().TrimEnd())" 
                                                                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                                        
                                                                        $MasterKeys += $RegistryKeyProperties
                                                                    }
                                                              }
                                                      }
                                              }
                                        }

                                      ForEach ($Key In $CUKeys)
                                        {
                                            $RegKey = $CURegKey.OpenSubkey($Key)
				                    
                                            If ($RegKey -ne $Null)
                                              {
                                                  ForEach ($SubName In $RegKey.GetSubKeyNames())
                                                      {
                                                          ForEach ($Sub In $RegKey.OpenSubKey($SubName))
                                                              {
                                                                  $DisplayName = $Sub.GetValue("DisplayName")
                                                                  
                                                                  If (($DisplayName -imatch $IncludeWithOptions) -and ($DisplayName -inotmatch $ExcludeWithOptions))
                                                                    {
                                                                        $LogMessage = "Now adding properties for the following software: `'$($DisplayName)`'. Please Wait..." 
                                                                        Write-Log -Message $LogMessage -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                                        
                                                                        $RegistryKeyProperties = New-Object -TypeName 'PSObject'
                                                                        $RegistryKeyProperties | Add-Member -Name "ComputerName" -Value ($Computer) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Path" -Value ($Sub.ToString()) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Name" -Value ($DisplayName) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "SystemComponent" -Value ($Sub.GetValue("SystemComponent")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "ParentKeyName" -Value ($Sub.GetValue("ParentKeyName")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Version" -Value ($Sub.GetValue("DisplayVersion")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "UninstallString" -Value ($Sub.GetValue("UninstallString")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "InstallLocation" -Value ($Sub.GetValue("InstallLocation")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "InstallSource" -Value ($Sub.GetValue("InstallSource")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "DisplayIcon" -Value ($Sub.GetValue("DisplayIcon")) -MemberType NoteProperty
                                                                        $RegistryKeyProperties | Add-Member -Name "Type" -Value "CurrentUser" -MemberType NoteProperty

                                                                        $LogMessage = "The following properties were found`r`n`r`n$(($RegistryKeyProperties | Format-List -Property * | Out-String).TrimStart().TrimEnd())" 
                                                                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                                                        
                                                                        $MasterKeys += $RegistryKeyProperties
                                                                    }
                                                              }
                                                      }
                                              }
                                        }
			            			            
                                      Write-Output -InputObject $MasterKeys
                                      
                                      If ($DisableFunctionLogging.IsPresent -eq $True)
                                        {
                                            $DisableLogging = $False
                                        }
                                  }
                                Else
                                  {
                                      $ErrorMessage = "Unable to connect to `'$($Computer)`'. Please verify its network connectivity and try again."
                                      Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                  }
                            }
                          Catch
                            {
                                $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True 
                                Throw "$($ErrorMessage)"
                            }
                  }
              }
          End
              { 
                  Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                  Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer 
              }
        }
#endregion

#region Function Test-Credential
Function Test-Credential
  { 
    [OutputType([Boolean])] 
     
    Param 
      ( 
        [Parameter(Mandatory = $True, ValueFromPipeLine = $True, ValueFromPipelineByPropertyName = $True)] 
        [Alias('PSCredential')] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential] 
        [System.Management.Automation.Credential()] 
        $Credential, 
 
        [Parameter()] 
        [String]$Domain = $Credential.GetNetworkCredential().Domain
      ) 
 
    Begin
      {
          [String]$CmdletName = $MyInvocation.MyCommand.Name 
          Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
          Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
          [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement") | Out-Null
          $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain, [System.DirectoryServices.AccountManagement.ContextOptions]'SecureSocketLayer,Negotiate') 
      } 
 
    Process 
      { 
        ForEach ($Item in $Credential)
          { 
            $NetworkCredential = $Credential.GetNetworkCredential()  
            Write-Output -InputObject $($PrincipalContext.ValidateCredentials($NetworkCredential.UserName, $NetworkCredential.Password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate)) 
          } 
      } 
 
    End
      { 
          $PrincipalContext.Dispose()
          Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
          Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
      } 
  }
#endregion

#region Function Get-MSPProperties
  Function Get-MSPProperties
    {
        [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = 'Path')]
       
          Param
            (
                [Parameter(Mandatory=$True, ParameterSetName = 'Path', ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullorEmpty()]
                [ValidateScript({(Test-Path -Path $_) -and (Test-Path -Path $_ -PathType Leaf) -and (([System.IO.Path]::GetExtension($_)) -ieq ".msp")})]
                [SupportsWildcards()]
                [Alias('FullName')]              
                [String[]]$Path,
                
                [Parameter(Mandatory=$True, ParameterSetName = 'LiteralPath', ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                [ValidateNotNullorEmpty()]
                [ValidateScript({(Test-Path -Path $_) -and (Test-Path -Path $_ -PathType Leaf) -and (([System.IO.Path]::GetExtension($_)) -ieq ".msp")})]
                [Alias('PSPath')]              
                [String[]]$LiteralPath,

                [Parameter(Mandatory=$False, ValueFromPipeline=$False)]
                [ValidateNotNullorEmpty()]
                [ValidateSet('Classification', 'Description', 'DisplayName', 'KBArticle Number', 'ManufacturerName', 'ReleaseVersion', 'TargetProductName')]
                [String[]]$MSPPropertyNames,
                
                [Parameter(Mandatory=$False)]
                [Switch]$Export,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullorEmpty()]
                [ValidatePattern('^(?:[\w]\:|\\)(\\[a-z_\-\s0-9\.]+)+\.(txt|log)$')]
                [String]$ExportPath
            )
        
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name 
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              
              If ((!($PSBoundParameters.ContainsKey('MSPPropertyNames'))) -and (($MSPPropertyNames | Measure-Object | Select-Object -ExpandProperty Count) -eq 0))
                {
                    [String[]]$MSPPropertyNames = (Get-Variable "MSPPropertyNames").Attributes.ValidValues | Sort-Object
                }
              
              If ($Export.IsPresent -eq $True)
                {                    
                    If ((!($PSBoundParameters.ContainsKey('ExportPath'))) -and ([String]::IsNullOrEmpty($ExportPath)))
                      {
                          $ExportPath = "$($CurrentConsoleUserSession_ProfileFolder_Documents)\$($CmdletName)\$($CmdletName)_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
                      }
                          
                    $ExportPathParent = Split-Path -Path $ExportPath -Parent
                        
                    If (!(Test-Path -Path $ExportPathParent)) {New-Folder -Path $ExportPathParent -Verbose -ContinueOnError:$False}
                        
                    If (Test-Path -Path $ExportPath) {Remove-File -Path $ExportPath -Verbose -ContinueOnError:$False}
                    
                    $StringBuilder = [System.Text.StringBuilder]::New()
                }

              [Int]$Script:MSPCounter = 0
        
              Try
                {
                    $oWindowsInstaller = New-Object -ComObject 'WindowsInstaller.Installer'
                }
              Catch
                {
                    Write-Log -Message "Failed to initialize the `'WindowsInstaller.Installer`' COM Object.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                    Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                }
          }

        Process
          {
            $Results = @()
          
            ForEach ($Item In $Path)
              {
                    Try
                      {
                        Write-Log -Message "Retrieving the file properties for `'$($Item)`'. Please Wait..." -Severity 1 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                        $PathProperties = Get-Item -Path "$($Item)"
                      }
                    Catch
                      {
                        Write-Log -Message "Failed to retrieve the file properties for `'$($Item)`'.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                        Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                      }
                                        
                    $PSObjectProperties = @{
                                              FileProperties = [System.IO.FileInfo]$PathProperties
                                           }
                    Try
                      { 
                          #Loads the MSI database and specifies the mode to open it in
                            $MSPDatabase = $oWindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $oWindowsInstaller, @($PathProperties.FullName, 32))
                            
                          $MSPProperties = @{}

                          ForEach ($MSPProperty In $MSPPropertyNames)
                            {
                                #Specifies to query the MSIPatchMetadata table and get the value associated with the designated property
                                  $Query = "SELECT Value FROM MsiPatchMetadata WHERE Property = '$($MSPProperty)'"
		                      
                                #Open up the property view
                                  $View = $MSPDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $Null, $MSPDatabase, ($Query))
                                  $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)
		                      
                                #Retrieve the associate Property
                                  $Record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $Null, $View, $Null)
		                      
                                #Retrieve the associated value of the retrieved property
                                  $Value = $Record.GetType().InvokeMember("StringData", "GetProperty", $Null, $Record, 1)
                                  
                                  If ($MSPProperty -ieq 'KBArticle Number')
                                    {
                                      $Value = "KB$($Value)"
                                    }
                                  
                                #Add each MSP Property to the hashtable
                                  $MSPProperties += @{$($MSPProperty) = "$($Value)"}                       
                            }

                          #Add the child hashtable to the parent hashtable
                            $PSObjectProperties.Add("MSPProperties", $MSPProperties)
                      }
                    Catch
                      {
                        Write-Log -Message "Failed to retrieve the Windows Installer properties for `'$($Item)`'.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                        Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                      }
                
                  $PSObject = New-Object -TypeName 'PSObject' -ArgumentList $PSObjectProperties
                  
                  $Results += $PSObject

                  $Script:MSPCounter++
                  
                  If ($Export.IsPresent -eq $True)
                    {
                        $ResultsToExport = $Results | Select-Object -Property @{Name="FilePath";Expression={$_.FileProperties.FullName}}, @{Name="UpdateName";Expression={$_.MSPProperties.DisplayName}}, @{Name="ArticleID";Expression={$_.MSPProperties.'KBArticle Number'}}, @{Name="Classification";Expression={$_.MSPProperties.Classification}}, @{Name="ProductName";Expression={$_.MSPProperties.TargetProductName}}, @{Name="Manufacturer";Expression={$_.MSPProperties.ManufacturerName}}
                        [String]$FormattedResultsToExport = "$(($ResultsToExport | Format-List | Out-String).TrimStart().TrimEnd())"
                        [Void]$StringBuilder.Append($FormattedResultsToExport)
                        [Void]$StringBuilder.AppendLine("")
                        [Void]$StringBuilder.AppendLine("")
                    }
                    
                  Try
                    {
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($MSPDatabase) | Out-Null
                    }
                  Catch
                    {
                          Write-Log -Message "Failed to release the following COM Object `'MSPDatabase`'.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                          Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                    }
                  
                  Try
                    {
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($View) | Out-Null
                    }
                  Catch
                    {
                          Write-Log -Message "Failed to release the following COM Object `'View`'..`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                          Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                    }
                  
                  Try
                    {
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Record) | Out-Null
                    }
                  Catch
                    {
                          Write-Log -Message "Failed to release the following COM Object `'Record`'.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                          Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                    }
                    
                  Write-Log -Message "The following MSP properties were extracted for`n`n$($PathProperties.FullName)`n`n$($Results.MSPProperties.GetEnumerator() | ForEach-Object {`"$($_.Name) = $($_.Value)`r`n`"})" -Severity 1 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
              }
        
            #Return the results to the powershell pipeline
              Write-Output -InputObject $Results
          }
        
        End
          {
                Try
                  {
                      [System.Runtime.Interopservices.Marshal]::ReleaseComObject($oWindowsInstaller) | Out-Null
                  }
                Catch
                  {
                        Write-Log -Message "Failed to release the following COM Object `'Windows Installer`'.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                        Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                  }
                  
                Try
                  {
                      [System.GC]::Collect()
                  }
                Catch
                  {
                        Write-Log -Message "Failed to collect the Global Assembly Cache.`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source ${CmdletName} -ContinueOnError:$True
                        Write-Error -Message "$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]"
                  }
                  
                $Item = $Null
                
                If ($Export.IsPresent -eq $True)
                  {
                      [Void]$StringBuilder.Append("MSP Count: $($Script:MSPCounter.ToString())")
                  
                      $StreamWriter = [System.IO.StreamWriter]::New($ExportPath)
                      [Void]$StreamWriter.Write($StringBuilder.ToString())
                      [Void]$StreamWriter.Close()
                      
                      Start-Sleep -Seconds 2
                        
                      If ($CurrentConsoleUserSession -ine $Null)
                        {
                            Try {Execute-ProcessAsUser -Path "$($envWinDir)\notepad.exe" -Parameters "`"$($ExportPath)`"" -RunLevel LeastPrivilege -PassThru -ExitOnProcessFailure:$False -ContinueOnError:$True} Catch {}
                        }
                      ElseIf ($CurrentConsoleUserSession -ieq $Null)
                        {
                            Try {Execute-Process -Path "$($envWinDir)\notepad.exe" -WorkingDirectory "$($ExportPathParent)" -Parameters "$($ExportPath)" -WindowStyle Normal -NoWait -PassThru -ExitOnProcessFailure:$False -ContinueOnError:$True} Catch {}
                        }
                  }
                    
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Select-CheckboxValue
  Function Select-CheckBoxValue
    {
        [CmdletBinding(SupportsShouldProcess=$True)]
       
          Param
            (
                [Parameter(Mandatory=$True)]
                [ValidateNotNullOrEmpty()]
                [Object]$InputObject,
                
                [Parameter(Mandatory=$True)]
                [ValidateNotNullOrEmpty()]
                [String]$CheckBoxContentProperty,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$CheckBoxToolTipProperty,

                [Parameter(Mandatory=$False)]
                [Switch]$CheckedByDefault,
                                                                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullorEmpty()]
                [ValidateScript({$_ -ilike "*.ico"})]
                [String]$IconPath,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullorEmpty()]            
                [String]$WindowTitle
            )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name
		          
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
        
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              
              Write-Log -Message "The following properties are available for use with the checkbox control(s)`n$(($InputObject | Get-Member -MemberType NoteProperty, Property | Sort-Object -Property Name | Select-Object -Property Name, MemberType, @{Name='Type';Expression={$_.Definition.Split()[0]}}| Out-String).TrimStart().TrimEnd() -Join "`r`n")" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
        
              Try
                {
                    [String]$Script:XAML = 
                @'
<Window
                        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                        WindowStartupLocation="CenterScreen"
                        Title="Select-CheckboxValue"
                        ShowInTaskbar="False"
                        Topmost="True"
                        SizeToContent="WidthAndHeight"
                        MinWidth="400"
                        MinHeight="190"
                        MaxWidth="800"
                        MaxHeight="600"
                        ResizeMode="NoResize"
                        Background="#F0F0F0">

    <Border>
        <StackPanel>

            <Label Name="LBL_TxtBox_Search_Checkboxes" Grid.Column="0" Grid.Row="0" Grid.ColumnSpan="1" Content="Search" FontSize="13" ToolTip="Please use a valid regular expression to search through any of the results located below." FontWeight="SemiBold"></Label>
            <TextBox Name="TxtBox_Search_Checkboxes" Grid.Column="1" Grid.Row="1" Grid.ColumnSpan="3" FontSize="16" IsReadOnly="False" Height="25" BorderBrush="Black" BorderThickness="0.8" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="10,4,10,0"></TextBox>

            <Grid Margin="5,10,5,10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <Grid.RowDefinitions>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <Border Name="Bdr_MainWindow_Checkboxes" Margin="5,5,5,5" BorderThickness="1.0" BorderBrush="Black">
                    <ScrollViewer Name="ScrlVwr_MainWindow_Checkboxes" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" CanContentScroll="True" BorderBrush="Black" BorderThickness="1.0">
                        <StackPanel Name="StkPnl_MainWindow_Checkboxes" Background="White" MaxWidth="680" MaxHeight="400">
                            <!-- Checkboxes can be placed here or added dynimically in the code behind -->
                        </StackPanel>
                    </ScrollViewer>
                </Border>
            </Grid>

            <Grid Margin="0,10,0,10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*" />
                </Grid.ColumnDefinitions>

                <Grid.RowDefinitions>
                    <RowDefinition Height="*" />
                </Grid.RowDefinitions>

                <Button Name="BTN_MainWindow_SelectAll" Grid.Column="0" Grid.ColumnSpan="1" MinWidth="90" Content="Select All" HorizontalAlignment="Center" FontSize="17" Margin="5,0,5,0" Foreground="#000000" FontWeight="SemiBold" Background="#E1E1E1" BorderThickness="1.5"></Button>
                <Button Name="BTN_MainWindow_DeselectAll" Grid.Column="1" Grid.ColumnSpan="1" MinWidth="90" Content="Deselect All" HorizontalAlignment="Center" FontSize="17" Margin="5,0,5,0" Foreground="#000000" FontWeight="SemiBold" Background="#E1E1E1" BorderThickness="1.5"></Button>
                <Button Name="BTN_MainWindow_OK" IsDefault="True" Grid.Column="2" Grid.ColumnSpan="1" MinWidth="90" Content="OK" HorizontalAlignment="Center" FontSize="17" Margin="5,0,5,0" Foreground="#000000" FontWeight="SemiBold" Background="#E1E1E1" BorderThickness="1.5"></Button>
                <Button Name="BTN_MainWindow_Cancel" IsCancel="True" Grid.Column="3" Grid.ColumnSpan="1" MinWidth="90" Content="Cancel" HorizontalAlignment="Center" FontSize="17" Margin="5,0,5,0" Foreground="#000000" FontWeight="SemiBold" IsDefault="True" Background="#E1E1E1" BorderThickness="1.5"></Button>

            </Grid>

        </StackPanel>

    </Border>

</Window>
'@

                    $Script:MainWindow_SlctChkBox = Convert-XAMLtoWindow -XAML $XAML -PassThru
                    
                    If ((!($PSBoundParameters.ContainsKey('IconPath'))) -and ([String]::IsNullOrEmpty($IconPath)))
                      {
                          $IconPath = "$($SCriptDirectory)\AppDeployToolkit\AppDeployToolkitLogo.ico"
                      }
                
                    If ((!($PSBoundParameters.ContainsKey('WindowTitle'))) -and ([String]::IsNullOrEmpty($WindowTitle)))
                      {
                          [String]$WindowTitle = "$($CmdletName)"
                      }
                      
                    If (Test-Path -Path $IconPath) {$Script:MainWindow_SlctChkBox.Icon = $IconPath}
                    
                    $Script:MainWindow_SlctChkBox.Title = $WindowTitle
                    
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_OK.Add_MouseEnter({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_OK.Add_MouseLeave({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_OK.Add_Click(
                      {
                          $Script:MainWindow_SlctChkBox.DialogResult = $True
                          $Script:MainWindow_SlctChkBox.Close()     
                      })

                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_Cancel.Add_MouseEnter({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_Cancel.Add_MouseLeave({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_Cancel.Add_Click(
                      {
                          $Script:MainWindow_SlctChkBox.DialogResult = $False
                          $Script:MainWindow_SlctChkBox.Close()
                      })
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
          }

        Process
          {           
              Try
                  {
                      [Int]$CheckboxCounter = 0
              
                      ForEach ($Item In $InputObject)
                        {
                            $CheckBoxVariableName = "StkPnl_MainWindow_Checkboxes_ChkBox_$($CheckBoxCounter)"
                            $CheckBoxVariableValue = New-Object -TypeName 'System.Windows.Controls.Checkbox'
                            $CheckBoxVariableDescription = "CheckBox Control for `'$($Item.$($CheckBoxNameProperty))`'"
      
                            $CreateCheckBoxControl = New-Variable -Name "$($CheckBoxVariableName)" -Value ($CheckBoxVariableValue) -Description "$($CheckBoxVariableDescription)" -Scope Script -Force
                            $CheckBoxControl = Get-Variable -Name "$($CheckBoxVariableName)" -Scope Script
      
                            If (!([String]::IsNullOrEmpty($Item.$($CheckBoxContentProperty)))) {$CheckBoxControl.Value.Content = "$($Item.$($CheckBoxContentProperty))"}
                            If (!([String]::IsNullOrEmpty($CheckBoxVariableName))) {$CheckBoxControl.Value.Name = "$($CheckBoxVariableName)"}     
                            If (!([String]::IsNullOrEmpty($Item.$($CheckBoxToolTipProperty)))) {$CheckBoxControl.Value.ToolTip = "$($Item.$($CheckBoxToolTipProperty))"}
                            $CheckBoxControl.Value.FontWeight = "SemiBold"
                            $CheckBoxControl.Value.FontSize = "13"
                            $CheckBoxControl.Value.Margin = "5,5,10,5"
                            $CheckBoxControl.Value.IsChecked = ($CheckedByDefault.IsPresent)
                                                 
                            $AddInputObjectProperties = Add-Member -InputObject ($CheckBoxControl.Value) -MemberType NoteProperty -Name "InputObjectProperties" -Value ($InputObject[$CheckBoxCounter])
      
                            [System.Windows.RoutedEventHandler]$Script:CheckBoxChecked = 
                              {
                                  $Sender = $This
                                  $Sender.IsChecked = $True
                              }
        
                            [System.Windows.RoutedEventHandler]$Script:CheckBoxUnchecked = 
                              {
                                  $Sender = $This
                                  $Sender.IsChecked = $False
                              }
  
                            $CheckBoxControl.Value.AddHandler([System.Windows.Controls.Checkbox]::CheckedEvent, $Script:CheckBoxChecked)
                            $CheckBoxControl.Value.AddHandler([System.Windows.Controls.Checkbox]::UncheckedEvent, $Script:CheckBoxUnchecked)
      
                            $Script:MainWindow_SlctChkBox.StkPnl_MainWindow_Checkboxes.AddChild($CheckBoxControl.Value)
                   
                            $CheckBoxControl = $Null

                            $CheckBoxCounter++
                        }
                        
                    $Script:Checkboxes = $Script:MainWindow_SlctChkBox.StkPnl_MainWindow_Checkboxes.Children | Where-Object {($_ -is [System.Windows.Controls.Checkbox])}
                    
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_SelectAll.Add_MouseEnter({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_SelectAll.Add_MouseLeave({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_SelectAll.Add_Click(
                      {
                          $CheckAllCheckboxes = $Script:Checkboxes | Where-Object {($_.Visibility -imatch 'Visible')} | ForEach-Object {($_.IsChecked = $True)}
                          Write-Log -Message "All visible checkboxes have been checked." -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      })

                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_DeselectAll.Add_MouseEnter({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_DeselectAll.Add_MouseLeave({$Script:MainWindow_SlctChkBox.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    $Script:MainWindow_SlctChkBox.BTN_MainWindow_DeselectAll.Add_Click(
                      {
                          $UncheckAllCheckboxes = $Script:Checkboxes | Where-Object {($_.Visibility -imatch 'Visible')} | ForEach-Object {($_.IsChecked = $False)}
                          Write-Log -Message "All visible checkboxes have been unchecked." -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      })

                    [System.Windows.RoutedEventHandler]$Script:TextChangedEventActions = 
                      {
                          Try
                            {
                                $Sender = $This
                                
                                $AllCheckboxes = $Script:Checkboxes
                                
                                If ($Sender.Text.Length -ge 1)
                                  {
                                      ForEach ($Checkbox In $AllCheckboxes)
                                        {
                                            If (($Checkbox.Content -imatch $Sender.Text) -or ($Checkbox.Tooltip.ToString() -imatch $Sender.Text))
                                              {
                                                  $Checkbox.Visibility = 'Visible'
                                              }
                                            Else
                                              {
                                                  $Checkbox.Visibility = 'Collapsed'
                                              }
                                        }
                                  }
                            }
                          Catch
                            {
                                $ErrorMessage = "Invalid Regular Expression - $($_.Exception.Message)"
                                Write-Log -Message $ErrorMessage -Severity 2 -LogType CMTrace -Source "$($Sender.Name)" -ContinueOnError:$True
                            }
                      }
  
                    $TxtBox_Search_Checkboxes = $Script:MainWindow_SlctChkBox.TxtBox_Search_Checkboxes
                    $TxtBox_Search_Checkboxes.AddHandler([System.Windows.Controls.TextBox]::TextChangedEvent, $TextChangedEventActions)
                      
                    $ShowDiaglog = Show-WPFWindow -Window $Script:MainWindow_SlctChkBox
              
                    $Checkboxes_Checked = $Script:Checkboxes | Where-Object {($_.IsChecked -eq $True)}
                    $Checkboxes_Checked_Count = $Checkboxes_Checked | Measure-Object | Select-Object -ExpandProperty Count
                    $Checkboxes_Unchecked = $Script:Checkboxes | Where-Object {($_.IsChecked -eq $False)}
                    $Checkboxes_Unchecked_Count = $Checkboxes_Unchecked | Measure-Object | Select-Object -ExpandProperty Count
                    
                    If ([Boolean]$ShowDiaglog -eq $True)
                      {
                          If ($Checkboxes_Checked_Count -gt 0) 
                            {
                                Write-Log -Message "There are `'$($Checkboxes_Checked_Count)`' checkboxes checked" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                Write-Log -Message "The following checkboxes were checked`n$(($Checkboxes_Checked | Select-Object -Property Name, Content, ToolTip | Out-String).TrimStart().TrimEnd() -Join "`r`n")" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                Write-Output -InputObject ([PSObject]$Checkboxes_Checked)
                            }
                          Else
                            {
                                Write-Log -Message "There are `'$($Checkboxes_Checked_Count)`' checkboxes checked" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                Write-Log -Message "There are `'$($Checkboxes_Unchecked_Count)`' checkboxes left unchecked" -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                Write-Output -InputObject ([Boolean]$ShowDiaglog)
                            }
                      }
                    ElseIf ([Boolean]$ShowDiaglog -eq $False)
                      {
                          Write-Log -Message "The dialog returned a result of $(([Boolean]$ShowDiaglog).ToString())" -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                          Throw "The dialog box was closed or canceled."
                      }   
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
          }
        
        End
          {                                        
                $Script:CheckBoxChecked = $Null
                $Script:CheckBoxUnchecked = $Null
                $Script:TextChangedEventActions = $Null
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Select-Date
  Function Select-Date
    {
        [CmdletBinding(SupportsShouldProcess=$True)]
       
          Param
            (
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [DateTime]$StartDate = ((Get-Date).AddDays(-7).Date),
				
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [DateTime]$EndDate = ((Get-Date).Date),
										
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [DateTime[]]$BlackOutDates,
								
                [Parameter(Mandatory=$False)]
                [ValidateNotNullorEmpty()]
                [String]$DateTimeStringFormat = 'dddd, MMMM dd, yyyy',
                                             
                [Parameter(Mandatory=$False)]
                [ValidateNotNullorEmpty()]
                [ValidateScript({$_ -ilike "*.ico"})]
                [String]$IconPath,
                
                [Parameter(Mandatory=$False)]
                [ValidateNotNullorEmpty()]            
                [String]$WindowTitle,

                [Parameter(Mandatory=$False)]           
                [Switch]$ContinueOnError
            )
                    
        Begin
          {
              [String]$CmdletName = $MyInvocation.MyCommand.Name
		          
              Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
        
              Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
              
              #Write-Log -Message "The following properties are available for use with the checkbox control(s)`n$(($InputObject | Get-Member -MemberType NoteProperty, Property | Sort-Object -Property Name | Select-Object -Property Name, MemberType, @{Name='Type';Expression={$_.Definition.Split()[0]}}| Out-String).TrimStart().TrimEnd() -Join "`r`n")" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
        
              $ErrorActionPreference = 'Continue'
							
              Try
                {
                    [String]$XAML = 
                @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    WindowStartupLocation="CenterScreen"
    ShowInTaskbar="False"
    Topmost="True"
    SizeToContent="WidthAndHeight"
    MaxWidth="500"
    MaxHeight="300"
    ResizeMode="NoResize"
    Background="#F0F0F0">

    <Border>
        <StackPanel>
            <GroupBox Name="GrpBox001" Header="Start Date" Margin="2,5,2,5" BorderBrush="Black" BorderThickness="1" FontWeight="DemiBold">
                <Grid Margin="0,0,0,10">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="Auto" />
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <Label Name="LBL_DatePickerStart" Grid.Column="0" Grid.Row="0" Grid.ColumnSpan="1" Content="Start Date:"></Label>
                    <DatePicker Name="DatePickerStart" Grid.Column="1" Grid.Row="0" Grid.ColumnSpan="3" Text="Please select a start date" MinHeight="25" MinWidth="250" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" IsTodayHighlighted="True"  Margin="4,4,4,4" BorderBrush="Black" BorderThickness="0.5"></DatePicker>
                    <Label Name="LBL_TxtBox001" Grid.Column="0" Grid.Row="1" Grid.ColumnSpan="1" Content="Selected Start Date:"></Label>
                    <TextBox Name="TxtBox001" Grid.Column="1" Grid.Row="1" Grid.ColumnSpan="3" FontSize="16" IsReadOnly="True" Height="25" BorderBrush="Black" BorderThickness="0.5" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="4,4,4,4"></TextBox>
                </Grid>
            </GroupBox>

            <GroupBox Name="GrpBox002" Header="End Date" Margin="2,5,2,5" BorderBrush="Black" BorderThickness="1" FontWeight="DemiBold">
                <Grid Margin="0,0,0,10">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="Auto" />
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <Label Name="LBL_DatePickerEnd" Grid.Column="0" Grid.Row="0" Grid.ColumnSpan="1" Content="End Date:"></Label>
                    <DatePicker Name="DatePickerEnd" Grid.Column="1" Grid.Row="0" Grid.ColumnSpan="3" MinHeight="25" MinWidth="250" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" IsTodayHighlighted="True"  Margin="4,4,4,4" BorderBrush="Black" BorderThickness="0.5"></DatePicker>
                    <Label Name="LBL_TxtBox002" Grid.Column="0" Grid.Row="1" Grid.ColumnSpan="1" Content="Selected End Date:"></Label>
                    <TextBox Name="TxtBox002" Grid.Column="1" Grid.Row="1" Grid.ColumnSpan="3" FontSize="16" IsReadOnly="True" Height="25" BorderBrush="Black" BorderThickness="0.5" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="4,4,4,4"></TextBox>
                </Grid>
            </GroupBox>
                
            <Grid Margin="10,10,10,10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Button Name="BTN_MainWindow_OK" IsDefault="True" Grid.Column="0" Grid.ColumnSpan="3" MinWidth="90" Content="OK" HorizontalAlignment="Center" FontSize="15" Margin="0,0,25,0" Foreground="#000000" FontWeight="SemiBold" Background="#E1E1E1" BorderThickness="1.5"></Button>
                <Button Name="BTN_MainWindow_Cancel" IsCancel="True" Grid.Column="1" Grid.ColumnSpan="4" MinWidth="90" Content="Cancel" HorizontalAlignment="Center" FontSize="15" Margin="25,0,0,0" Foreground="#000000" FontWeight="SemiBold" IsDefault="True" Background="#E1E1E1" BorderThickness="1.5"></Button>
            </Grid>
        </StackPanel>
    </Border>
</Window>
'@

                    $MainWindow = Convert-XAMLtoWindow -XAML $XAML -PassThru
                    
                    If ((!($PSBoundParameters.ContainsKey('IconPath'))) -and ([String]::IsNullOrEmpty($IconPath)))
                      {
                          $IconPath = "$($SCriptDirectory)\AppDeployToolkit\AppDeployToolkitLogo.ico"
                      }
                
                    If ((!($PSBoundParameters.ContainsKey('WindowTitle'))) -and ([String]::IsNullOrEmpty($WindowTitle)))
                      {
                          [String]$WindowTitle = "$($CmdletName)"
                      }
                      
                    If (Test-Path -Path $IconPath) {$MainWindow.Icon = $IconPath}
                    
                    $MainWindow.Title = $WindowTitle

                    $MainWindow.DatePickerStart.Add_MouseEnter({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $MainWindow.DatePickerStart.Add_MouseLeave({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Arrow})
										
                    $MainWindow.DatePickerEnd.Add_MouseEnter({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $MainWindow.DatePickerEnd.Add_MouseLeave({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    
                    $MainWindow.BTN_MainWindow_OK.Add_MouseEnter({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $MainWindow.BTN_MainWindow_OK.Add_MouseLeave({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    $MainWindow.BTN_MainWindow_OK.Add_Click(
                      {
                          $MainWindow.DialogResult = $True
                          $MainWindow.Close()     
                      })

                    $MainWindow.BTN_MainWindow_Cancel.Add_MouseEnter({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Hand})
                    $MainWindow.BTN_MainWindow_Cancel.Add_MouseLeave({$MainWindow.Cursor = [System.Windows.Input.Cursors]::Arrow})
                    $MainWindow.BTN_MainWindow_Cancel.Add_Click(
                      {
                          $MainWindow.DialogResult = $False
                          $MainWindow.Close()
                      })
                }
              Catch
                {
                    Write-Log -Message "Failed to initialize the required components of function `'$($CmdletName)`'`r`n`r`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                }
          }

        Process
          {           
              Try
                  {
                      $MainWindow.TxtBox001.Text = $StartDate.ToString($DateTimeStringFormat)
											
                      $MainWindow.DatePickerStart.SelectedDateFormat = [System.Windows.Controls.DatePickerFormat]::Short
											
                      $MainWindow.DatePickerStart.FirstDayOfWeek = "Sunday"
											
                      $MainWindow.DatePickerStart.IsDropDownOpen = $False
											
                      $MainWindow.DatePickerStart.IsTodayHighlighted = $True
											
                      $MainWindow.DatePickerStart.SelectedDate = $StartDate
                      $MainWindow.DatePickerStart.DisplayDateEnd = (Get-Date).Date
											
                      $MainWindow.TxtBox002.Text = $EndDate.ToString($DateTimeStringFormat)
											
                      $MainWindow.DatePickerEnd.SelectedDateFormat = [System.Windows.Controls.DatePickerFormat]::Short
											
                      $MainWindow.DatePickerEnd.FirstDayOfWeek = "Sunday"
											
                      $MainWindow.DatePickerEnd.IsDropDownOpen = $False
											
                      $MainWindow.DatePickerEnd.IsTodayHighlighted = $True
											
                      $MainWindow.DatePickerEnd.SelectedDate = $EndDate
                      $MainWindow.DatePickerEnd.DisplayDateEnd = (Get-Date).Date
								
                      If ($BlackOutDates -ne $Null)
                        {
                            ForEach ($BlackOutDate In $BlackOutDates)
                              {	
                                  $LogMessage = "Adding the following black out date: `'$($BlackOutDate.Date.ToString($DateTimeStringFormat))`'. Please Wait..."
                                  Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
																	
                                  $MainWindow.DatePickerStart.BlackoutDates.Add([System.Windows.Controls.CalendarDateRange]::New($BlackOutDate))
                                  $MainWindow.DatePickerEnd.BlackoutDates.Add([System.Windows.Controls.CalendarDateRange]::New($BlackOutDate))
                              }
                        }

                      [System.Windows.RoutedEventHandler]$SelectedDateChanged_DatePickerStart = 
                        {
                            $Sender = $This
                            $SelectedDateAsString = "$($Sender.SelectedDate.ToString($DateTimeStringFormat))"
                            $MainWindow.TxtBox001.Text = $SelectedDateAsString
                            Write-Log -Message "Selected Date was changed to: `'$($SelectedDateAsString)`' [Control Name: $($Sender.Name)]" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                        }
												
                      [System.Windows.RoutedEventHandler]$SelectedDateChanged_DatePickerEnd = 
                        {
                            $Sender = $This
                            $SelectedDateAsString = "$($Sender.SelectedDate.ToString($DateTimeStringFormat))"
                            $MainWindow.TxtBox002.Text = $SelectedDateAsString
                            Write-Log -Message "Selected Date was changed to: `'$($SelectedDateAsString)`' [Control Name: $($Sender.Name)]" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                        }

                      $MainWindow.DatePickerStart.AddHandler([System.Windows.Controls.DatePicker]::SelectedDateChangedEvent, $SelectedDateChanged_DatePickerStart)
                      $MainWindow.DatePickerEnd.AddHandler([System.Windows.Controls.DatePicker]::SelectedDateChangedEvent, $SelectedDateChanged_DatePickerEnd)
										
                      $ShowDiaglog = Show-WPFWindow -Window $MainWindow
											
                      $ReturnObject = New-Object -TypeName 'PSObject'
											
                      [DateTime]$SelectedStartDate = $MainWindow.DatePickerStart.SelectedDate
                      $ReturnObject | Add-Member -Name "StartDate" -Value ($SelectedStartDate) -MemberType NoteProperty
											
                      $LogMessage = "Selected Start Date: `'$($SelectedStartDate.Date.ToString($DateTimeStringFormat))`'"
                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
											
                      [DateTime]$SelectedEndDate = $MainWindow.DatePickerEnd.SelectedDate
                      $ReturnObject | Add-Member -Name "EndDate" -Value ($SelectedEndDate) -MemberType NoteProperty
											
                      $LogMessage = "Selected End Date: `'$($SelectedEndDate.Date.ToString($DateTimeStringFormat))`'"
                      Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
											
                      [Timespan]$Timespan_StartToEnd = New-TimeSpan -Start ($SelectedStartDate) -End ($SelectedEndDate)  
                      $ReturnObject | Add-Member -Name "Timespan" -Value ($Timespan_StartToEnd) -MemberType NoteProperty
											
                      If ($SelectedStartDate -lt $SelectedEndDate)
                        {
                            [Int[]]$Timespan_Days = $Timespan_StartToEnd.Days..0
                        }
                      ElseIf ($SelectedStartDate -ge $SelectedEndDate)
                        {
                            [Int[]]$Timespan_Days = 0..$Timespan_StartToEnd.Days
                        }
											
                      [DateTime[]]$DateRange = @()
								
                      ForEach ($Day In $Timespan_Days)
                        {
                            $DateRange += [DateTime]$SelectedStartDate.AddDays($Day)
                        }
											
                      $ReturnObject | Add-Member -Name "DateRange" -Value ($DateRange | Sort-Object -Property Date) -MemberType NoteProperty
											
                      $ReturnObject | Add-Member -Name "BlackoutDates" -Value ($BlackOutDates) -MemberType NoteProperty
                      
                      $ReturnObject | Add-Member -Name "DialogResult" -Value ([String]::New($MainWindow.DialogResult.ToString())) -MemberType NoteProperty 
											
                      If (($ReturnObject.DialogResult -eq $False) -and ($ContinueOnError.IsPresent -eq $False))
                        {
                            Throw "The operation was canceled."
                        }
                      
                      #Write Powershell Object to the Powershell Pipeline										
                        Write-Output -InputObject ($ReturnObject)
                }
              Catch
                {
                    $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                    Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                    If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                }
          }
        
        End
          {                                        
                $MainWindow.DatePickerStart.RemoveHandler([System.Windows.Controls.DatePicker]::SelectedDateChangedEvent, $SelectedDateChanged_DatePickerStart)
                $MainWindow.DatePickerEnd.RemoveHandler([System.Windows.Controls.DatePicker]::SelectedDateChangedEvent, $SelectedDateChanged_DatePickerEnd)
                
                Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
          }
    }
#endregion

#region Function Get-AdministrativePrivilege
Function Get-AdministrativePrivilege
    {
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
        Write-Output -InputObject ($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    }
#endregion

#region Function New-RandomPassword
    #Generate Complex Password
        Function New-RandomPassword
            {
              [CmdletBinding(SupportsShouldProcess=$False)]
                Param
                    (
                        [Parameter(Mandatory=$False)]
                        [Int]$PasswordLength = $(Get-Random -Minimum 8 -Maximum 15),
                                    
                        [Parameter(Mandatory=$False)]
                        [Int]$NonAlphaNumericCharCount = $(Get-Random -Minimum 2 -Maximum 4),

                        [Parameter(Mandatory=$False)]
                        [Alias('DPWL')]
                        [Switch]$DisablePasswordLogging,

                        [Parameter(Mandatory=$False)]
                        [Switch]$ContinueOnError
                    )

                Begin
                    {
                        [String]$CmdletName = $MyInvocation.MyCommand.Name 
                        Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                        Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                        $ErrorActionPreference = 'Stop'

                        $LogMessage = "The following parameters and values were provided to the `'$($CmdletName)`' function." 
                        Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True

                        $FunctionProperties = Get-Command -Name $CmdletName
              
                        ForEach ($Parameter In $FunctionProperties.Parameters.Keys)
                          {
                              If (!([String]::IsNullOrEmpty($Parameter)))
                                {
                                    $ParameterProperties = Get-Variable -Name $Parameter -ErrorAction SilentlyContinue
                                    $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                    If (!([String]::IsNullOrEmpty($ParameterProperties.Name)))
                                      {
                                          $LogMessage = "$($ParameterProperties.Name): $($ParameterValueStringFormat)" 
                                          Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                      }
                                }
                          }
                    }
          
                Process
                      {
                        Try
                          {
                              Add-Type -AssemblyName System.Web | Out-Null
                              $RandomPassword = "$([System.Web.Security.Membership]::GeneratePassword($PasswordLength, $NonAlphaNumericCharCount))"
                              
                              If ($DisablePasswordLogging.IsPresent -eq $True)
                                {
                                    $LogMessage = "Randomly Generated Password: `'$($RandomPassword)`'"
                                    Write-Log -Message $LogMessage -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                                }
                              
                              Write-Output "$($RandomPassword.ToString())"
                          }
                        Catch
                          {
                              $ErrorMessage = "$($CmdletName):`r`n`r`n[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                              Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                    
                              If ($ContinueOnError.IsPresent -eq $False) {Throw "$($ErrorMessage)"}
                          }
                      }

                End
                  {                                        
                        Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                        Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
                  }
            }
#endregion

#region Function Copy-ItemUsingExplorer
    Function Copy-ItemUsingExplorer
        {          
            [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = 'Path')]
                Param
                    (  
                        [Parameter(Mandatory=$True, ParameterSetName = 'Path', ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
                        [ValidateNotNullorEmpty()]
                        [ValidateScript({(Test-Path -Path $_)})]
                        [SupportsWildcards()]
                        [Alias('FullName')]              
                        [String[]]$Path,
                                                    
                        [Parameter(Mandatory=$True)]
                        [ValidateScript({[Int]$_.ToCharArray().Count -le [Int]"255"})]
                        [String]$Destination,
                                    
                        [Parameter(Mandatory=$False)]
                        [Int32]$CopyFlags = 16
                    )
            
                Begin
                  {
                      [String]$CmdletName = $MyInvocation.MyCommand.Name
                      Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                      Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                      
                      $CopyFlags = "0x" + [String]::Format("{0:x}", $CopyFlags)
                      $RefreshPSDrives = Get-PSDrive -ErrorAction SilentlyContinue
                      If (!(Test-Path -Path $Destination)) {(New-Folder -Path $Destination -Verbose -ContinueOnError:$False)}
                      
                      [System.IO.DirectoryInfo]$DestinationProperties = $Destination
                  }
              
                Process
                  {
                      $ResolvedPaths = Resolve-Path -Path $Path | Select-Object -ExpandProperty ProviderPath

                      ForEach ($Item In $ResolvedPaths)
                        {
                            Try
                              {
                                  If (Test-Path -Path $Item -PathType Leaf)
                                    {
                                        [System.IO.FileInfo]$ItemProperties = $Item  
                                      
                                        Write-Log -Message "Attempting to copy item `'$($ItemProperties.FullName)`' to destination `'$($DestinationProperties.FullName)`'" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True 

                                        $oDestination = (New-Object -ComObject Shell.Application).Namespace($DestinationProperties.FullName)
                                        $oDestination.CopyHere($ItemProperties.FullName, $CopyFlags)
                                    }
                                  ElseIf (Test-Path -Path $Item -PathType Container)
                                    {
                                        [System.IO.DirectoryInfo]$ItemProperties = $Item
                                        
                                        Write-Log -Message "Attempting to copy item(s) contained within `'$($ItemProperties.FullName)\*`' to destination `'$($DestinationProperties.FullName)`'" -Severity 1 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True 
                                    
                                        $oItem = (New-Object -ComObject Shell.Application).Namespace($ItemProperties.FullName)
                                        $oDestination = (New-Object -ComObject Shell.Application).Namespace($DestinationProperties.FullName)
                                        $oDestination.CopyHere($oItem.Items(), $CopyFlags)
                                    }
                                    
                                  If ($? -eq $True)
                                    {
                                        Write-Output $True
                                    }
                                  ElseIf ($? -eq $False)
                                    {
                                        Write-Output $False
                                    }
                              }
                            Catch
                              {
                                  Write-Output $False
                                  Write-Log -Message "`n$($_.Exception.Message) [Line Number: $($_.InvocationInfo.ScriptLineNumber)]" -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              }
                        }
                  }
              
                End
                  {
                      Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                      Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
                  }
        }
#endregion

#region Function Select-ListBoxValue
    Function Select-ListBoxValue
        { 
            [CmdletBinding()]
                Param
                    (        
                        [Parameter(Mandatory=$False, HelpMessage="Please enter a valid icon path")]
                        [ValidateNotNullOrEmpty()]
                        [ValidateScript({(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.exe")})]		
                        [String]$IconPath = "$($PSHOME)\powershell.exe",	        

                        [Parameter(Mandatory=$False)]		
                        [ValidateNotNullOrEmpty()]
                        [String]$Title = "$($MyInvocation.MyCommand)",
                        
                        [Parameter(Mandatory=$False)]		
                        [ValidateNotNullOrEmpty()]
                        [String]$Message = "Please select the Windows Image Edition you want to keep`r`n`r`n(Only one selection can be made. All other editions will be removed.)",
                                    
                        [Parameter(Mandatory=$False)]		
                        [String[]]$ListBoxObject = ((Get-NetAdapter).InterfaceDescription),
                                                            
                        [Parameter(Mandatory=$False)]		
                        [ValidateNotNullOrEmpty()]
                        [ValidateSet('One', 'MultiSimple', 'MultiExtended')]
                        [String]$SelectionMode = "One"                  
                    )
                    
            Begin
                {
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -CmdletBoundParameters $PSBoundParameters -Header
                    Write-Log -Message "Function `'$($CmdletName)`' is beginning. Please Wait..." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                } 
                
            Process
                {
                    Try
                      {
                          #Setup the form 
                              [Void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
                              [Void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")  

                              $Form_Main = New-Object System.Windows.Forms.Form  
                              $Form_Main.Text = "$($Title)"
                              If (Test-Path -Path $IconPath) {$Form_Main.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($IconPath)}
                              $Form_Main.Size = New-Object System.Drawing.Size(435,310)  
                              $Form_Main.StartPosition = "CenterScreen"
                              $Form_Main.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Fixed3D
                              $Form_Main.MaximizeBox = $False
                              $Form_Main.MinimizeBox = $False
                              $Button_OK = New-Object System.Windows.Forms.Button 
                              $Button_OK.Location = New-Object System.Drawing.Size(120,240) 
                              $Button_OK.Size = New-Object System.Drawing.Size(75,23)
                              $Button_OK.Text = "OK"
                              $Button_OK.DialogResult = [System.Windows.Forms.DialogResult]::OK
                              $Form_Main.AcceptButton = $Button_OK
                              $Form_Main.Controls.Add($Button_OK) 
      
                              $Button_Cancel = New-Object System.Windows.Forms.Button 
                              $Button_Cancel.Location = New-Object System.Drawing.Size(200,240) 
                              $Button_Cancel.Size = New-Object System.Drawing.Size(75,23) 
                              $Button_Cancel.Text = "Cancel" 
                              $Button_Cancel.Add_Click({$Form_Main.Close()}) 
                              $Form_Main.Controls.Add($Button_Cancel) 
 
                              $Label_Main = New-Object System.Windows.Forms.Label  
                              $Label_Main.Location = New-Object System.Drawing.Size(10,20)  
                              $Label_Main.Size = New-Object System.Drawing.Size(350,40)  
                              $Label_Main.Text = "$($Message)"
                              $Form_Main.Controls.Add($Label_Main)  
  
                              $ListBox_Main = New-Object System.Windows.Forms.ListBox 
                              $ListBox_Main.Location = New-Object System.Drawing.Size(10,60)  
                              $ListBox_Main.Size = New-Object System.Drawing.Size(400,380)  
                              $ListBox_Main.Height = 180 
                              $ListBox_Main.SelectionMode = "$($SelectionMode)"
 
                          #Adds the values to the list box 
                              ForEach ($Item In $ListBoxObject)
                                  { 
                                      [Void]($ListBox_Main.Items.Add(($Item)))
                                  } 
  
                          $Form_Main.Controls.Add($ListBox_Main)  
                          $Form_Main.Topmost = $True 
                          $Form_Main.Add_Shown({$Form_Main.Activate()}) 
                          $Result = $Form_Main.ShowDialog((New-Object 'System.Windows.Forms.Form' -Property @{TopMost = $True}))

                          If ($Result -ieq [System.Windows.Forms.DialogResult]::OK)
                              {
                                  If (!([String]::IsNullOrEmpty($ListBox_Main.SelectedItems))) {Return $ListBox_Main.SelectedItems} Else {Return "Invalid"}
                              }
                          Else
                              {
                                  Return "Invalid"
                              }
                              }
                            Catch
                              {
                                  $ErrorMessage = "$($CmdletName): $($_.Exception.Message)`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"
                                  Write-Log -Message $ErrorMessage -Severity 3 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True
                              }
                }
                
          End
            {                                        
                  Write-Log -Message "Function `'$($CmdletName)`' is completed." -Severity 2 -LogType CMTrace -Source "$($CmdletName)" -ContinueOnError:$True            
                  Write-FunctionHeaderOrFooter -CmdletName "$($CmdletName)" -Footer
            }
        }
#endregion

##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================

If ($scriptParentPath) {
	Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $appDeployToolkitExtName
} Else {
	Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $appDeployToolkitExtName
}

##*===============================================
##* END SCRIPT BODY
##*===============================================
