#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepares Windows Server for win-acme and installs it.

.DESCRIPTION
    This script performs pre-flight checks, fixes common issues, and installs
    win-acme for automated SSL certificate management. Supports Windows Server
    2012 and later.

.PARAMETER InstallPath
    The path where win-acme will be installed. Default: C:\Tools\win-acme

.PARAMETER SkipDotNetCheck
    Skip .NET Framework version check.

.PARAMETER SkipTLS12Check
    Skip TLS 1.2 configuration check.

.PARAMETER Force
    Force reinstallation even if win-acme is already installed.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\Install-Prerequisites.ps1

.EXAMPLE
    .\Install-Prerequisites.ps1 -InstallPath 'D:\Tools\win-acme' -Force

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$InstallPath = 'C:\Tools\win-acme',

    [Parameter()]
    [switch]$SkipDotNetCheck,

    [Parameter()]
    [switch]$SkipTLS12Check,

    [Parameter()]
    [switch]$Force
)

# Import common functions
$commonPath = Join-Path $PSScriptRoot '..\Helpers\Common.ps1'
if (Test-Path $commonPath) {
    . $commonPath
}
else {
    Write-Error "Common.ps1 not found at: $commonPath"
    exit 1
}

# Initialize
Initialize-WinCertManager
Write-Log 'Starting Windows Certificate Manager Prerequisites Installation' -Level Info

# Results tracking
$results = [PSCustomObject]@{
    OSVersion = $null
    TLS12Status = $null
    DotNetStatus = $null
    PowerShellVersion = $null
    WinAcmeInstalled = $false
    RequiresReboot = $false
    Errors = @()
    Warnings = @()
}

#region OS Version Check
Write-Log 'Checking Operating System version...' -Level Info

$osInfo = Get-OSVersion
$results.OSVersion = $osInfo

Write-Log "Detected: $($osInfo.Caption) (Build $($osInfo.BuildNumber))" -Level Info

if ($osInfo.Name -eq 'Unknown') {
    $results.Warnings += 'Unknown Windows version detected. Script may not work correctly.'
    Write-Log $results.Warnings[-1] -Level Warning
}

if ($osInfo.Is2012) {
    Write-Log 'Server 2012/2012 R2 detected. Additional configuration may be required.' -Level Warning
}
#endregion

#region PowerShell Version Check
Write-Log 'Checking PowerShell version...' -Level Info

$psVersion = $PSVersionTable.PSVersion
$results.PowerShellVersion = $psVersion

if ($psVersion.Major -lt 5) {
    $results.Warnings += "PowerShell version $psVersion detected. Version 5.1 is recommended."
    Write-Log $results.Warnings[-1] -Level Warning
}
else {
    Write-Log "PowerShell version: $psVersion (OK)" -Level Info
}
#endregion

#region TLS 1.2 Check
if (-not $SkipTLS12Check) {
    Write-Log 'Checking TLS 1.2 configuration...' -Level Info

    $tlsEnabled = Test-TLS12Enabled

    if ($tlsEnabled) {
        Write-Log 'TLS 1.2 is enabled (OK)' -Level Info
        $results.TLS12Status = 'Enabled'
    }
    else {
        Write-Log 'TLS 1.2 is not properly configured.' -Level Warning

        if ($PSCmdlet.ShouldProcess('TLS 1.2 Registry Settings', 'Enable')) {
            Enable-TLS12
            $results.TLS12Status = 'Configured (Reboot Required)'
            $results.RequiresReboot = $true
            Write-Log 'TLS 1.2 has been enabled. A reboot is required.' -Level Warning
        }
        else {
            $results.TLS12Status = 'Not Configured'
            $results.Warnings += 'TLS 1.2 is not enabled. Run with -WhatIf:$false to enable.'
        }
    }
}
else {
    Write-Log 'Skipping TLS 1.2 check.' -Level Info
    $results.TLS12Status = 'Skipped'
}
#endregion

#region .NET Framework Check
if (-not $SkipDotNetCheck) {
    Write-Log 'Checking .NET Framework version...' -Level Info

    $dotNet = Get-DotNetVersion

    if ($dotNet.Installed) {
        Write-Log ".NET Framework version: $($dotNet.Version)" -Level Info

        if ($dotNet.MeetsMinimum) {
            Write-Log '.NET Framework 4.7.2+ requirement met (OK)' -Level Info
            $results.DotNetStatus = $dotNet.Version
        }
        else {
            $results.Warnings += ".NET Framework $($dotNet.Version) detected. Version 4.7.2+ is recommended for best compatibility."
            Write-Log $results.Warnings[-1] -Level Warning
            $results.DotNetStatus = "$($dotNet.Version) (Upgrade Recommended)"

            # Provide download link
            Write-Log 'Download .NET Framework 4.8 from: https://dotnet.microsoft.com/download/dotnet-framework/net48' -Level Info
        }
    }
    else {
        $results.Errors += '.NET Framework 4.x is not installed. win-acme requires .NET Framework 4.7.2+'
        Write-Log $results.Errors[-1] -Level Error
        $results.DotNetStatus = 'Not Installed'
    }
}
else {
    Write-Log 'Skipping .NET Framework check.' -Level Info
    $results.DotNetStatus = 'Skipped'
}
#endregion

#region Check Existing Installation
Write-Log 'Checking for existing win-acme installation...' -Level Info

$existingPath = Get-WinAcmePath

if ($existingPath -and -not $Force) {
    Write-Log "win-acme is already installed at: $existingPath" -Level Info
    Write-Log 'Use -Force to reinstall.' -Level Info
    $results.WinAcmeInstalled = $true

    # Check version
    $wacsPath = Join-Path $existingPath 'wacs.exe'
    if (Test-Path $wacsPath) {
        $version = (Get-Item $wacsPath).VersionInfo.ProductVersion
        Write-Log "Installed version: $version" -Level Info
    }
}
#endregion

#region Download and Install win-acme
if (-not $results.WinAcmeInstalled -or $Force) {
    Write-Log 'Preparing to download win-acme...' -Level Info

    # Ensure TLS 1.2 for download
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Get latest release from GitHub
    $apiUrl = 'https://api.github.com/repos/win-acme/win-acme/releases/latest'

    try {
        Write-Log 'Fetching latest release information from GitHub...' -Level Info

        $releaseInfo = Invoke-WithRetry -Description 'GitHub API request' -ScriptBlock {
            Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -Headers @{
                'User-Agent' = 'WinCertManager/1.0'
            }
        }

        $version = $releaseInfo.tag_name
        Write-Log "Latest version: $version" -Level Info

        # Find the correct asset (pluggable version, x64)
        $asset = $releaseInfo.assets | Where-Object {
            $_.name -match 'win-acme.*pluggable.*x64.*\.zip$' -and
            $_.name -notmatch 'trimmed'
        } | Select-Object -First 1

        if (-not $asset) {
            # Fallback to any x64 zip
            $asset = $releaseInfo.assets | Where-Object {
                $_.name -match 'win-acme.*x64.*\.zip$'
            } | Select-Object -First 1
        }

        if (-not $asset) {
            throw 'Could not find appropriate win-acme release asset.'
        }

        $downloadUrl = $asset.browser_download_url
        $fileName = $asset.name

        Write-Log "Downloading: $fileName" -Level Info

        # Create temp directory
        $tempDir = Join-Path $env:TEMP 'win-acme-install'
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

        $zipPath = Join-Path $tempDir $fileName

        # Download file
        if ($PSCmdlet.ShouldProcess($downloadUrl, 'Download')) {
            Invoke-WithRetry -Description 'Download win-acme' -ScriptBlock {
                Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
            }

            Write-Log 'Download complete.' -Level Info

            # Create installation directory
            if (-not (Test-Path $InstallPath)) {
                New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
            }
            elseif ($Force) {
                # Backup existing installation
                $backupPath = "$InstallPath.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
                Write-Log "Backing up existing installation to: $backupPath" -Level Info
                Move-Item -Path $InstallPath -Destination $backupPath -Force
                New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
            }

            # Extract archive
            Write-Log "Extracting to: $InstallPath" -Level Info
            Expand-Archive -Path $zipPath -DestinationPath $InstallPath -Force

            # Verify installation
            $wacsExe = Join-Path $InstallPath 'wacs.exe'
            if (Test-Path $wacsExe) {
                # SECURITY: Verify Authenticode signature before trusting the binary
                Write-Log 'Verifying Authenticode signature...' -Level Info
                $signature = Get-AuthenticodeSignature -FilePath $wacsExe

                if ($signature.Status -eq 'Valid') {
                    # Verify the signer is the expected publisher (win-acme is signed by "Certify The Web")
                    $signerName = $signature.SignerCertificate.Subject
                    Write-Log "Binary signed by: $signerName" -Level Info

                    if ($signerName -match 'Certify The Web|win-acme') {
                        Write-Log 'Authenticode signature verified successfully' -Level Info
                    }
                    else {
                        Write-Log "Warning: Binary signed by unexpected publisher: $signerName" -Level Warning
                        $results.Warnings += "win-acme binary signed by unexpected publisher: $signerName"
                    }
                }
                elseif ($signature.Status -eq 'NotSigned') {
                    Write-Log 'Warning: win-acme binary is not digitally signed. This may be expected for some releases.' -Level Warning
                    $results.Warnings += 'win-acme binary is not digitally signed'
                }
                else {
                    # Invalid signature is a serious security concern
                    Write-Log "ERROR: Authenticode signature validation failed: $($signature.Status)" -Level Error
                    $results.Errors += "Authenticode signature validation failed: $($signature.Status). Binary may have been tampered with."

                    # Remove the potentially compromised installation
                    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
                    throw "Security Error: Authenticode signature validation failed ($($signature.Status)). Installation aborted."
                }

                Write-Log 'win-acme installed successfully.' -Level Info
                $results.WinAcmeInstalled = $true

                # Get installed version
                $installedVersion = (Get-Item $wacsExe).VersionInfo.ProductVersion
                Write-Log "Installed version: $installedVersion" -Level Info
            }
            else {
                throw 'wacs.exe not found after extraction.'
            }

            # Clean up temp files
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        $results.Errors += "Failed to download/install win-acme: $($_.Exception.Message)"
        Write-Log $results.Errors[-1] -Level Error
    }
}
#endregion

#region Create Scheduled Task
if ($results.WinAcmeInstalled) {
    Write-Log 'Checking scheduled task for renewals...' -Level Info

    $taskName = 'win-acme renew'
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

    if ($existingTask) {
        Write-Log 'Scheduled task already exists.' -Level Info
    }
    else {
        Write-Log 'Creating scheduled task for automatic renewals...' -Level Info

        if ($PSCmdlet.ShouldProcess($taskName, 'Create Scheduled Task')) {
            $wacsPath = if ($results.WinAcmeInstalled -and (Test-Path $InstallPath)) {
                $InstallPath
            }
            else {
                Get-WinAcmePath
            }

            $wacsExe = Join-Path $wacsPath 'wacs.exe'

            # Create the scheduled task
            $action = New-ScheduledTaskAction -Execute $wacsExe -Argument '--renew --baseuri https://acme-v02.api.letsencrypt.org/'
            $trigger = New-ScheduledTaskTrigger -Daily -At '9:00AM'
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

            try {
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Automatic certificate renewal via win-acme' | Out-Null
                Write-Log 'Scheduled task created successfully.' -Level Info
            }
            catch {
                $results.Warnings += "Failed to create scheduled task: $($_.Exception.Message)"
                Write-Log $results.Warnings[-1] -Level Warning
                Write-Log 'You may need to create the scheduled task manually using wacs.exe --setuptaskscheduler' -Level Info
            }
        }
    }
}
#endregion

#region Summary
Write-Log '' -Level Info
Write-Log '========================================' -Level Info
Write-Log '         INSTALLATION SUMMARY' -Level Info
Write-Log '========================================' -Level Info
Write-Log '' -Level Info
Write-Log "Operating System:   $($results.OSVersion.Caption)" -Level Info
Write-Log "PowerShell Version: $($results.PowerShellVersion)" -Level Info
Write-Log "TLS 1.2 Status:     $($results.TLS12Status)" -Level Info
Write-Log ".NET Framework:     $($results.DotNetStatus)" -Level Info
Write-Log "win-acme Installed: $($results.WinAcmeInstalled)" -Level Info

if ($results.WinAcmeInstalled) {
    $wacsPath = if (Test-Path $InstallPath) { $InstallPath } else { Get-WinAcmePath }
    Write-Log "win-acme Location:  $wacsPath" -Level Info
}

if ($results.RequiresReboot) {
    Write-Log '' -Level Info
    Write-Log '*** REBOOT REQUIRED ***' -Level Warning
    Write-Log 'TLS 1.2 settings have been changed. Please reboot before using win-acme.' -Level Warning
}

if ($results.Warnings.Count -gt 0) {
    Write-Log '' -Level Info
    Write-Log 'WARNINGS:' -Level Warning
    foreach ($warning in $results.Warnings) {
        Write-Log "  - $warning" -Level Warning
    }
}

if ($results.Errors.Count -gt 0) {
    Write-Log '' -Level Info
    Write-Log 'ERRORS:' -Level Error
    foreach ($errorItem in $results.Errors) {
        Write-Log "  - $errorItem" -Level Error
    }
}

Write-Log '' -Level Info
Write-Log '========================================' -Level Info

# Return results object
$results
#endregion
