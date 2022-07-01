<#
Script to remove HP and Microsoft bloatware
Original: https://gist.github.com/mark05e/a79221b4245962a477a49eb281d97388
Modified by Joachim Berghmans

To run the script manually or using Intune you will need to copy the file uninstallHPCO.iss to C:\windows\install manually.
This script is meant to be wrapped as an intunewin file and deployed during Autopilot or as a Win32 app
Do not not forget to include uninstallHPCO.iss when creating your Win32 app by saving the file in the same folder as your script

#>

Add-Type -AssemblyName PresentationCore, PresentationFramework


function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "Remove-HP-Bloatware.log"
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath "Install") -ChildPath $FileName
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""RemoveHPBloatware"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            if ($Severity -eq 1) {
                Write-Output -Message $Value
            } else {
                Write-Warning -Message $Value
            }
        }
    }



#Remove HP Documentation
if (Test-Path "C:\Program Files\HP\Documentation\Doc_uninstall.cmd" -PathType Leaf){
Try {
    Invoke-Item "C:\Program Files\HP\Documentation\Doc_uninstall.cmd"
    Write-LogEntry -Value "Successfully removed provisioned package: HP Documentation" -Severity 1
    }
Catch {
        Write-LogEntry -Value  "Error Remvoving HP Documentation $($_.Exception.Message)" -Severity 3
        }
}
Else {
        Write-LogEntry -Value  "HP Documentation is not installed" -Severity 1
}

#Remove HP Support Assistant silently

# $HPSAuninstall = "C:\Program Files (x86)\HP\HP Support Framework\UninstallHPSA.exe"

# if (Test-Path -Path "HKLM:\Software\WOW6432Node\Hewlett-Packard\HPActiveSupport") {
# Try {
#         Remove-Item -Path "HKLM:\Software\WOW6432Node\Hewlett-Packard\HPActiveSupport"
#         Write-LogEntry -Value  "HP Support Assistant regkey deleted $($_.Exception.Message)" -Severity 1
#     }
# Catch {
#         Write-LogEntry -Value  "Error retreiving registry key for HP Support Assistant: $($_.Exception.Message)" -Severity 3
#         }
# }
# Else {
#         Write-LogEntry -Value  "HP Support Assistant regkey not found" -Severity 1
# }

# if (Test-Path $HPSAuninstall -PathType Leaf) {
#     Try {
#         & $HPSAuninstall /s /v/qn UninstallKeepPreferences=FALSE
#         Write-LogEntry -Value "Successfully removed provisioned package: HP Support Assistant silently" -Severity 1
#     }
#         Catch {
#         Write-LogEntry -Value  "Error uninstalling HP Support Assistant: $($_.Exception.Message)" -Severity 3
#         }
# }
# Else {
#         Write-LogEntry -Value  "HP Support Assistant Uninstaller not found" -Severity 1
# }


#Remove HP Connection Optimizer

$HPCOuninstall = "C:\Program Files (x86)\InstallShield Installation Information\{6468C4A5-E47E-405F-B675-A70A70983EA6}\setup.exe"

#create uninstall file
$uninstallHPCO = @"
[InstallShield Silent]
Version=v7.00
File=Response File
[File Transfer]
OverwrittenReadOnly=NoToAll
[{6468C4A5-E47E-405F-B675-A70A70983EA6}-DlgOrder]
Dlg0={6468C4A5-E47E-405F-B675-A70A70983EA6}-MessageBox-0
Count=2
Dlg1={6468C4A5-E47E-405F-B675-A70A70983EA6}-SdFinish-0
[{6468C4A5-E47E-405F-B675-A70A70983EA6}-MessageBox-0]
Result=6
[Application]
Name=HP Connection Optimizer
Version=2.0.19.0
Company=HP
Lang=0413
[{6468C4A5-E47E-405F-B675-A70A70983EA6}-SdFinish-0]
Result=1
bOpt1=0
bOpt2=0
"@
$uninstallHPCOFile = "$($env:USERPROFILE)\Desktop\uninstallHPCO.iss"
$uninstallHPCO | Out-File $uninstallHPCOFile

Write-LogEntry -Value  "Succesfully created file uninstallHPCO.iss on Desktop " -Severity 1

if (Test-Path $HPCOuninstall -PathType Leaf){
Try {
        & $HPCOuninstall -runfromtemp -l0x0413  -removeonly -s -f1$uninstallHPCOFile
        Write-LogEntry -Value "Successfully removed HP Connection Optimizer" -Severity 1
        }
Catch {
        Write-LogEntry -Value  "Error uninstalling HP Connection Optimizer: $($_.Exception.Message)" -Severity 3
        }
}
Else {
        Write-LogEntry -Value  "HP Connection Optimizer not found" -Severity 1
}


#List of packages to install
$UninstallPackages = @(
    "AD2F1837.HPJumpStarts"
    "AD2F1837.HPPCHardwareDiagnosticsWindows"
    "AD2F1837.HPPowerManager"
    "AD2F1837.HPPrivacySettings"
    # "AD2F1837.HPSupportAssistant"
    "AD2F1837.HPSureShieldAI"
    "AD2F1837.HPSystemInformation"
    "AD2F1837.HPQuickDrop"
    "AD2F1837.HPWorkWell"
    "AD2F1837.myHP"
    "AD2F1837.HPDesktopSupportUtilities"
    "AD2F1837.HPEasyClean"
    "AD2F1837.HPSystemInformation"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.People"
    "Microsoft.StorePurchaseApp"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.XboxApp"
    "Microsoft.Wallet"
    "Microsoft.SkypeApp"
    "Microsoft.BingWeather"
    "Tile.TileWindowsApplication"
)

# List of programs to uninstall
$UninstallPrograms = @(
    "HP Connection Optimizer"
    "HP Documentation"
    "HP MAC Address Manager"
    "HP Notifications"
    "HP Security Update Service"
    "HP System Default Settings"
    "HP Sure Click"
    "HP Sure Run"
    "HP Sure Recover"
    "HP Sure Sense"
    "HP Sure Sense Installer"
    "HP Wolf Security Application Support for Sure Sense"
    "HP Wolf Security Application Support for Windows"
    "HP Client Security Manager"
    "HP Wolf Security"
)

#Get a list of installed packages matching our list
$InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {($UninstallPackages -contains $_.Name)}

#Get a list of Provisioned packages matching our list
$ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object  {($UninstallPackages -contains $_.DisplayName)}

#Get a list of installed programs matching our list
$InstalledPrograms = Get-Package | Where-Object  {$UninstallPrograms -contains $_.Name}


# Remove provisioned packages first
ForEach ($ProvPackage in $ProvisionedPackages) {

    Write-LogEntry -Value "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]" -Severity 1

    Try {
        $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
        Write-LogEntry -Value "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]" -Severity 1
    }
    Catch {
        Write-LogEntry -Value  "Failed to remove provisioned package: [$($ProvPackage.DisplayName)] Error message: $($_.Exception.Message)" -Severity 3
    }
}

# Remove appx packages
ForEach ($AppxPackage in $InstalledPackages) {
                                            
    Write-LogEntry -Value "Attempting to remove Appx package: [$($AppxPackage.Name)] " -Severity 1

    Try {
        $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
        Write-LogEntry -Value "Successfully removed Appx package: [$($AppxPackage.Name)]" -Severity 1
    }
    Catch {
        Write-LogEntry -Value  "Failed to remove Appx package: [$($AppxPackage.Name)] Error message: $($_.Exception.Message)" -Severity 3
    }
}

# Remove installed programs
$InstalledPrograms | ForEach-Object {

    Write-LogEntry -Value "Attempting to uninstall: [$($_.Name)]"  -Severity 1

    Try {
        $Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
        Write-LogEntry -Value "Successfully uninstalled: [$($_.Name)]" -Severity 1
    }
    Catch {
        Write-LogEntry -Value  "Failed to uninstall: [$($_.Name)] Error message: $($_.Exception.Message)" -Severity 3
    }
}

#Fallback attempt 1 to remove HP Wolf Security using msiexec
Try {
    MsiExec /x "{0E2E04B0-9EDD-11EB-B38C-10604B96B11E}" /qn /norestart
    Write-LogEntry -Value "Fallback to MSI uninistall for HP Wolf Security initiated" -Severity 1
}
Catch {
    Write-LogEntry -Value  "Failed to uninstall HP Wolf Security using MSI - Error message: $($_.Exception.Message)" -Severity 3
}

#Fallback attempt 2 to remove HP Wolf Security using msiexec
Try {
    MsiExec /x "{4DA839F0-72CF-11EC-B247-3863BB3CB5A8}" /qn /norestart
    Write-LogEntry -Value "Fallback to MSI uninistall for HP Wolf 2 Security initiated" -Severity 1
}
Catch {
    Write-LogEntry -Value  "Failed to uninstall HP Wolf Security 2 using MSI - Error message: $($_.Exception.Message)" -Severity 3
}


#Remove shortcuts
$pathTCO = "C:\ProgramData\HP\TCO"
$pathTCOc = "C:\Users\Public\Desktop\TCO Certified.lnk"
$pathOS = "C:\Program Files (x86)\Online Services"
$pathFT = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Free Trials.lnk"

if (Test-Path $pathTCO) {
    Try {
        Remove-Item -LiteralPath $pathTCO -Force -Recurse
        Write-LogEntry -Value "Shortcut for $pathTCO removed" -Severity 1
    }
        Catch {
        Write-LogEntry -Value  "Error deleting $pathTCO $($_.Exception.Message)" -Severity 3
        }
    }
Else {
        Write-LogEntry -Value  "Folder $pathTCO not found" -Severity 1
}

if (Test-Path $pathTCOc -PathType Leaf) {
    Try {
        Remove-Item -Path $pathTCOc  -Force -Recurse
        Write-LogEntry -Value "Shortcut for $pathTCOc removed" -Severity 1
    }
        Catch {
        Write-LogEntry -Value  "Error deleting $pathTCOc $($_.Exception.Message)" -Severity 3
        }
    }
Else {
        Write-LogEntry -Value  "File $pathTCOc not found" -Severity 1
}

if (Test-Path $pathOS) {
    Try {
        Remove-Item -LiteralPath $pathOS  -Force -Recurse
        Write-LogEntry -Value "Shortcut for $pathOS removed" -Severity 1
    }
        Catch {
        Write-LogEntry -Value  "Error deleting $pathOS $($_.Exception.Message)" -Severity 3
        }
    }
Else {
        Write-LogEntry -Value  "Folder $pathOS not found" -Severity 1
}

    if (Test-Path $pathFT -PathType Leaf) {
    Try {
        Remove-Item -Path $pathFT -Force -Recurse
        Write-LogEntry -Value "Shortcut for $pathFT removed" -Severity 1
    }
        Catch {
        Write-LogEntry -Value  "Error deleting $pathFT $($_.Exception.Message)" -Severity 3
        }
    }
Else {
        Write-LogEntry -Value  "File $pathFT not found" -Severity 1
}

#Clean up uninstall file for HP Connection Optimizer
Remove-Item -Path $uninstallHPCOFile -Force
Write-LogEntry -Value  "Succesfully deleted file uninstallHPCO.iss" -Severity 1

$WshShell = New-Object -comObject WScript.Shell
$Files = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" -Filter *.lnk -Recurse
foreach ($File in $Files) {
    $FilePath = $File.FullName
    $Shortcut = $WshShell.CreateShortcut($FilePath)
    $Target = $Shortcut.TargetPath
    if (Test-Path -Path $Target) {
    } else {
        Write-LogEntry -Value "Invalid Shortcut: $($File.BaseName) removed." -Severity 1
        try {
            Remove-Item -Path $FilePath
        } catch {
            Write-LogEntry -Value "ERROR: $($File.BaseName) could not be removed." -Severity 3
        }
    }
}

function UninstallOneDrive {

    Write-Host "Checking for pre-existing files and folders located in the OneDrive folders..."
    Start-Sleep 1
    If (Test-Path "$env:USERPROFILE\OneDrive\*") {
        Write-Host "Files found within the OneDrive folder! Checking to see if a folder named OneDriveBackupFiles exists."
        Start-Sleep 1
              
        If (Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles") {
            Write-Host "A folder named OneDriveBackupFiles already exists on your desktop. All files from your OneDrive location will be moved to that folder." 
        }
        else {
            If (!(Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles")) {
                Write-Host "A folder named OneDriveBackupFiles will be created and will be located on your desktop. All files from your OneDrive location will be located in that folder."
                New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
                Write-Host "Successfully created the folder 'OneDriveBackupFiles' on your desktop."
            }
        }
        Start-Sleep 1
        Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
        Write-Host "Successfully moved all files/folders from your OneDrive folder to the folder 'OneDriveBackupFiles' on your desktop."
        Start-Sleep 1
        Write-Host "Proceeding with the removal of OneDrive."
        Start-Sleep 1
    }
    Else {
        Write-Host "Either the OneDrive folder does not exist or there are no files to be found in the folder. Proceeding with removal of OneDrive."
        Start-Sleep 1
        Write-Host "Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'."
        $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
        If (!(Test-Path $OneDriveKey)) {
            Mkdir $OneDriveKey
            Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
        }
        Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
    }

    Write-Host "Uninstalling OneDrive. Please wait..."
    

    New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Stop-Process -Name "OneDrive*"
    Start-Sleep 2
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"

        New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Stop-Process -Name "OneDrive*"
        Start-Sleep 2
        If (!(Test-Path $onedrive)) {
            $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        }
        Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
        Start-Sleep 2
        Write-Output "Stopping explorer"
        Start-Sleep 1
        taskkill.exe /F /IM explorer.exe
        Start-Sleep 3
        Write-Output "Removing leftover files"
        Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
        Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
        Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
        If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
            Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
        }
        Write-Output "Removing OneDrive from windows explorer"
        If (!(Test-Path $ExplorerReg1)) {
            New-Item $ExplorerReg1
        }
        Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
        If (!(Test-Path $ExplorerReg2)) {
            New-Item $ExplorerReg2
        }
        Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
        Write-Output "Restarting Explorer that was shut down before."
        Start-Process explorer.exe -NoNewWindow
    
        Write-Host "Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'."
        $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
        If (!(Test-Path $OneDriveKey)) {
            Mkdir $OneDriveKey 
        }
        Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
        Start-Sleep 2
        Write-Host "Stopping explorer"
        Start-Sleep 1
        taskkill.exe /F /IM explorer.exe
        Start-Sleep 3
        Write-Host "Removing leftover files"
        If (Test-Path "$env:USERPROFILE\OneDrive") {
            Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
        }
        If (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") {
            Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
        }
        If (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") {
            Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
        }
        If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
            Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
        }
        Write-Host "Removing OneDrive from windows explorer"
        If (!(Test-Path $ExplorerReg1)) {
            New-Item $ExplorerReg1
        }
        Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
        If (!(Test-Path $ExplorerReg2)) {
            New-Item $ExplorerReg2
        }
        Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
        Write-Host "Restarting Explorer that was shut down before."
        Start-Process explorer.exe -NoNewWindow
        Write-Host "OneDrive has been successfully uninstalled!"
        
        Remove-item env:OneDrive
    }
}

$Button = [Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [Windows.MessageBoxImage]::Error
$WarnIco = [Windows.MessageBoxImage]::Warning

$Prompt1 = [Windows.MessageBox]::Show("Do you want to uninstall One Drive?", "Delete OneDrive", $Button, $ErrorIco) 
Switch ($Prompt1) {
    Yes {
        UninstallOneDrive
        Write-LogEntry -Value "OneDrive is now removed from the computer." -Severity 1
    }
    No {
        Write-LogEntry -Value "You have chosen to skip removing OneDrive from your machine." -Severity 1
    }
}

Function UnpinStart {
    # https://superuser.com/a/1442733
    #Requires -RunAsAdministrator

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

    $layoutFile="C:\Windows\StartMenuLayout.xml"

    #Delete layout file if it already exists
    If(Test-Path $layoutFile)
    {
        Remove-Item $layoutFile
    }

    #Creates the blank layout file
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

    $regAliases = @("HKLM", "HKCU")

    #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        IF(!(Test-Path -Path $keyPath)) { 
            New-Item -Path $basePath -Name "Explorer"
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }

    #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Stop-Process -name explorer
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5

    #Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
    }

    #Restart Explorer and delete the layout file
    Stop-Process -name explorer

    # Uncomment the next line to make clean start menu default for all new users
    #Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

    Remove-Item $layoutFile
}

$Prompt2 = [Windows.MessageBox]::Show("Do you want to unpin all Start Menu Items", "Unpin", $Button, $ErrorIco) 
Switch ($Prompt2) {
    Yes {
        UnpinStart
        Write-Host "Start Apps unpined."
    }
    No {
        Write-Host "Apps will remain pinned to the start menu."

    }
}

Write-LogEntry -Value "Removed broken Shortcuts" -Severity 1

powercfg.exe -x -monitor-timeout-ac 0
powercfg.exe -x -monitor-timeout-dc 0
powercfg.exe -x -disk-timeout-ac 0
powercfg.exe -x -disk-timeout-dc 0
powercfg.exe -x -standby-timeout-ac 0
powercfg.exe -x -standby-timeout-dc 0
powercfg.exe -x -hibernate-timeout-ac 0
powercfg.exe -x -hibernate-timeout-dc 0

Write-LogEntry -Value "Successfuly set Power Settings" -Severity 1
