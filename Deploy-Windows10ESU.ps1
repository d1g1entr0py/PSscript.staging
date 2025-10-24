<#
.SYNOPSIS
    Deploys Windows 10 ESU (Extended Security Update) license keys via Kaseya VSA.

.DESCRIPTION
    This script installs and activates Windows 10 ESU license keys on endpoints.
    It accepts a MAK (Multiple Activation Key) as a parameter, installs the license,
    activates it, and optionally reboots the system if needed.

.PARAMETER MAKKey
    The Windows 10 ESU Multiple Activation Key (MAK) in format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

.PARAMETER ESUYear
    The ESU year to activate (1, 2, or 3).
    Year 1: 2025-2026, Year 2: 2026-2027, Year 3: 2027-2028
    Default is 1.

.PARAMETER AutoReboot
    If set to $true, the system will automatically reboot after successful activation.
    Default is $false.

.PARAMETER LogPath
    Path where the log file will be created. Default is C:\Windows\Temp\ESU_Deployment.log

.EXAMPLE
    .\Deploy-Windows10ESU.ps1 -MAKKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" -ESUYear 1 -AutoReboot $true

.NOTES
    Author: Generated for Kaseya VSA Deployment
    Version: 2.0
    Requires: Administrator privileges

    ESU Activation IDs:
    - Year 1 (2025-2026): f520e45e-7413-4a34-a497-d2765967d094
    - Year 2 (2026-2027): 1043add5-23b1-4afb-9a0f-64343c8f3f8d
    - Year 3 (2027-2028): 83d49986-add3-41d7-ba33-87c7bfb5c0fb
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the Windows 10 ESU MAK Key")]
    [ValidatePattern('^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$')]
    [string]$MAKKey,

    [Parameter(Mandatory=$false, HelpMessage="Enter the ESU Year (1, 2, or 3)")]
    [ValidateSet(1, 2, 3)]
    [int]$ESUYear = 1,

    [Parameter(Mandatory=$false)]
    [bool]$AutoReboot = $false,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Windows\Temp\ESU_Deployment.log"
)

# ESU Activation IDs per year
$ESUActivationIDs = @{
    1 = "f520e45e-7413-4a34-a497-d2765967d094"  # Year 1: 2025-2026
    2 = "1043add5-23b1-4afb-9a0f-64343c8f3f8d"  # Year 2: 2026-2027
    3 = "83d49986-add3-41d7-ba33-87c7bfb5c0fb"  # Year 3: 2027-2028
}

# Initialize logging
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to console
    switch ($Level) {
        'Error'   { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Success' { Write-Output "[SUCCESS] $Message" }
        default   { Write-Output $Message }
    }

    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction Stop
    } catch {
        Write-Warning "Unable to write to log file: $_"
    }
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Get current Windows license status
function Get-LicenseStatus {
    try {
        Write-Log "Retrieving current license status..." -Level Info
        $licenseStatus = cscript.exe //NoLogo C:\Windows\System32\slmgr.vbs /dli
        return $licenseStatus
    } catch {
        Write-Log "Failed to retrieve license status: $_" -Level Error
        return $null
    }
}

# Install the ESU product key
function Install-ESUKey {
    param (
        [string]$ProductKey
    )

    try {
        Write-Log "Installing ESU product key..." -Level Info

        # Install the product key using slmgr
        $installResult = cscript.exe //NoLogo C:\Windows\System32\slmgr.vbs /ipk $ProductKey 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Log "Product key installed successfully" -Level Success
            return $true
        } else {
            Write-Log "Failed to install product key. Exit code: $LASTEXITCODE. Output: $installResult" -Level Error
            return $false
        }
    } catch {
        Write-Log "Exception occurred while installing product key: $_" -Level Error
        return $false
    }
}

# Activate the ESU license
function Activate-ESULicense {
    param (
        [string]$ActivationID
    )

    try {
        Write-Log "Activating ESU license with Activation ID: $ActivationID..." -Level Info

        # Activate the license with the specific ESU Activation ID
        $activateResult = cscript.exe //NoLogo C:\Windows\System32\slmgr.vbs /ato $ActivationID 2>&1

        # Wait a moment for activation to complete
        Start-Sleep -Seconds 5

        if ($LASTEXITCODE -eq 0) {
            Write-Log "License activated successfully" -Level Success
            return $true
        } else {
            Write-Log "Failed to activate license. Exit code: $LASTEXITCODE. Output: $activateResult" -Level Error
            return $false
        }
    } catch {
        Write-Log "Exception occurred while activating license: $_" -Level Error
        return $false
    }
}

# Verify ESU activation
function Test-ESUActivation {
    param (
        [string]$ActivationID
    )

    try {
        Write-Log "Verifying ESU activation status for Activation ID: $ActivationID..." -Level Info

        # Get detailed license information for the specific ESU Activation ID
        $licenseInfo = cscript.exe //NoLogo C:\Windows\System32\slmgr.vbs /dlv $ActivationID 2>&1

        # Convert output to string if it's an array
        if ($licenseInfo -is [array]) {
            $licenseInfoStr = $licenseInfo -join "`n"
        } else {
            $licenseInfoStr = $licenseInfo
        }

        Write-Log "License information retrieved" -Level Info

        # Check if the license status indicates activation
        if ($licenseInfoStr -match "License Status: Licensed") {
            Write-Log "ESU license is active and licensed" -Level Success
            return $true
        } else {
            Write-Log "ESU license verification failed. License may not be activated." -Level Warning
            Write-Log "License Info: $licenseInfoStr" -Level Info
            return $false
        }
    } catch {
        Write-Log "Exception occurred while verifying activation: $_" -Level Error
        return $false
    }
}

# Reboot the system
function Restart-SystemIfNeeded {
    param (
        [bool]$Force
    )

    if ($Force) {
        Write-Log "Initiating system reboot in 60 seconds..." -Level Warning
        Write-Log "Reboot can be cancelled by running: shutdown /a" -Level Info

        # Schedule reboot in 60 seconds with a message
        shutdown.exe /r /t 60 /c "System reboot required to complete Windows 10 ESU license activation. This reboot was initiated by ESU deployment script." /d p:0:0

        Write-Log "Reboot scheduled successfully" -Level Success
    } else {
        Write-Log "AutoReboot is disabled. Please reboot the system manually to complete the activation." -Level Warning
    }
}

# Main execution block
try {
    Write-Log "=== Windows 10 ESU License Deployment Started ===" -Level Info
    Write-Log "Script Version: 2.0" -Level Info
    Write-Log "Execution Time: $(Get-Date)" -Level Info

    # Get the Activation ID for the specified ESU year
    $activationID = $ESUActivationIDs[$ESUYear]
    Write-Log "ESU Year: $ESUYear ($(2024 + $ESUYear)-$(2025 + $ESUYear))" -Level Info
    Write-Log "Activation ID: $activationID" -Level Info

    # Check for Administrator privileges
    if (-not (Test-Administrator)) {
        Write-Log "This script requires Administrator privileges. Please run as Administrator." -Level Error
        exit 1
    }
    Write-Log "Administrator privileges confirmed" -Level Success

    # Validate Windows version
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $osInfo.Caption
    Write-Log "Operating System: $osVersion" -Level Info

    if ($osVersion -notmatch "Windows 10") {
        Write-Log "This script is designed for Windows 10. Current OS: $osVersion" -Level Warning
    }

    # Display current license status
    Write-Log "=== Current License Status ===" -Level Info
    $currentStatus = Get-LicenseStatus
    if ($currentStatus) {
        Write-Log $currentStatus -Level Info
    }

    # Mask the key for logging (show only first and last 5 characters)
    $maskedKey = $MAKKey.Substring(0, 5) + "-XXXXX-XXXXX-XXXXX-" + $MAKKey.Substring($MAKKey.Length - 5)
    Write-Log "MAK Key to be installed: $maskedKey" -Level Info

    # Install the ESU product key
    Write-Log "=== Installing ESU Product Key ===" -Level Info
    $installSuccess = Install-ESUKey -ProductKey $MAKKey

    if (-not $installSuccess) {
        Write-Log "Failed to install ESU product key. Aborting." -Level Error
        exit 1
    }

    # Activate the ESU license with the specific Activation ID
    Write-Log "=== Activating ESU License ===" -Level Info
    $activateSuccess = Activate-ESULicense -ActivationID $activationID

    if (-not $activateSuccess) {
        Write-Log "Failed to activate ESU license. Manual intervention may be required." -Level Error
        exit 1
    }

    # Verify activation using the specific Activation ID
    Write-Log "=== Verifying Activation ===" -Level Info
    $verifySuccess = Test-ESUActivation -ActivationID $activationID

    if ($verifySuccess) {
        Write-Log "ESU license has been successfully installed and activated!" -Level Success

        # Display final license status for the specific ESU
        Write-Log "=== Final ESU License Status ===" -Level Info
        $finalESUStatus = cscript.exe //NoLogo C:\Windows\System32\slmgr.vbs /dlv $activationID
        if ($finalESUStatus) {
            Write-Log $finalESUStatus -Level Info
        }

        # Handle reboot if requested
        if ($AutoReboot) {
            Restart-SystemIfNeeded -Force $true
        } else {
            Write-Log "No automatic reboot requested. If updates fail to install, a manual reboot may be required." -Level Info
        }

        Write-Log "=== Windows 10 ESU License Deployment Completed Successfully ===" -Level Success
        exit 0
    } else {
        Write-Log "ESU license activation could not be verified. Please check the license status manually." -Level Warning
        Write-Log "Run 'slmgr.vbs /dlv $activationID' to view detailed license information." -Level Info
        exit 1
    }

} catch {
    Write-Log "An unexpected error occurred: $_" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}
