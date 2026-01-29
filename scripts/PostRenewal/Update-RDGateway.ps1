#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Updates RD Gateway SSL certificate binding after renewal.

.DESCRIPTION
    This script is called by win-acme after a certificate renewal to update
    the Remote Desktop Gateway SSL binding. It finds the renewed certificate
    and rebinds it to the RD Gateway service.

.PARAMETER Thumbprint
    The thumbprint of the renewed certificate.

.PARAMETER Subject
    The subject (CN) of the certificate to find. Used if thumbprint not provided.

.PARAMETER RestartService
    Restart the RD Gateway service after updating the binding.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\Update-RDGateway.ps1 -Thumbprint 'ABC123...'

.EXAMPLE
    .\Update-RDGateway.ps1 -Subject 'gateway.example.com' -RestartService

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0

    This script should be configured as a win-acme installation script:
    wacs.exe ... --installation script --script "Update-RDGateway.ps1" --scriptparameters "-Thumbprint {CertThumbprint}"
#>

[CmdletBinding(SupportsShouldProcess)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '',
    Justification = 'RD Gateway TSGatewayServer WMI namespace requires WMI cmdlets for method invocation')]
param(
    [Parameter(ParameterSetName = 'Thumbprint')]
    [string]$Thumbprint,

    [Parameter(ParameterSetName = 'Subject')]
    [string]$Subject,

    [Parameter()]
    [switch]$RestartService
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
Write-Log 'Starting RD Gateway certificate update' -Level Info

# Logging helper
$loggingScript = Join-Path $PSScriptRoot '..\Logging\Send-CertificateEvent.ps1'

function Send-Event {
    param($EventType, $Domain, $Thumbprint, $Message, $Status)
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript -EventType $EventType -Domain $Domain -Thumbprint $Thumbprint -Message $Message -Status $Status
        }
        catch {
            Write-Log "Failed to send event: $($_.Exception.Message)" -Level Verbose
        }
    }
}

# Verify RD Gateway is installed
$tsGatewayService = Get-Service -Name 'TSGateway' -ErrorAction SilentlyContinue
if (-not $tsGatewayService) {
    $errorMsg = 'RD Gateway service (TSGateway) is not installed on this server.'
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain 'Unknown' -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

Write-Log "RD Gateway service status: $($tsGatewayService.Status)" -Level Info

# Find the certificate
$certificate = $null

if ($Thumbprint) {
    Write-Log "Looking for certificate with thumbprint: $Thumbprint" -Level Info
    $certificate = Get-CertificateByThumbprint -Thumbprint $Thumbprint
}
elseif ($Subject) {
    Write-Log "Looking for certificate with subject: $Subject" -Level Info
    $certificate = Get-CertificateBySubject -Subject $Subject -Latest
}
else {
    $errorMsg = 'Either -Thumbprint or -Subject must be specified.'
    Write-Log $errorMsg -Level Error
    throw $errorMsg
}

if (-not $certificate) {
    $errorMsg = "Certificate not found. Thumbprint: $Thumbprint, Subject: $Subject"
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain ($Subject ?? 'Unknown') -Thumbprint $Thumbprint -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

Write-Log "Found certificate: $($certificate.Subject) (Thumbprint: $($certificate.Thumbprint))" -Level Info
Write-Log "Certificate expires: $($certificate.NotAfter)" -Level Info

# Validate certificate
$validation = Test-CertificateValid -Certificate $certificate -RequirePrivateKey
if (-not $validation.IsValid) {
    $errorMsg = "Certificate validation failed: $($validation.Issues -join ', ')"
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain $certificate.Subject -Thumbprint $certificate.Thumbprint -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

# Get domain from certificate
$domain = $certificate.Subject -replace '^CN=', '' -replace ',.*$', ''

# Import RemoteDesktopServices module if available
$rdsModule = Get-Module -ListAvailable -Name RemoteDesktopServices
if ($rdsModule) {
    Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue
}

# Update RD Gateway certificate binding
Write-Log 'Updating RD Gateway certificate binding...' -Level Info

try {
    if ($PSCmdlet.ShouldProcess('RD Gateway', 'Update SSL Certificate Binding')) {

        # Method 1: Using RD Gateway PowerShell provider (preferred)
        if (Test-Path 'RDS:\GatewayServer\SSLCertificate') {
            Write-Log 'Using RD Gateway PowerShell provider' -Level Verbose

            # Set the certificate thumbprint
            Set-Item -Path 'RDS:\GatewayServer\SSLCertificate\Thumbprint' -Value $certificate.Thumbprint -Force

            Write-Log 'Certificate binding updated via RDS provider' -Level Info
        }
        # Method 2: Using WMI (fallback)
        else {
            Write-Log 'Using WMI method (RDS provider not available)' -Level Verbose

            $tsGateway = Get-WmiObject -Namespace 'root\TSGatewayServer' -Class 'Win32_TSGatewayServerSettings' -ErrorAction Stop

            # Set the SSL certificate
            $result = $tsGateway.SetSSLCertificate($certificate.Thumbprint)

            if ($result.ReturnValue -ne 0) {
                throw "WMI SetSSLCertificate returned error code: $($result.ReturnValue)"
            }

            Write-Log 'Certificate binding updated via WMI' -Level Info
        }

        # Optionally restart the service
        if ($RestartService) {
            Write-Log 'Restarting RD Gateway service...' -Level Info

            Restart-Service -Name 'TSGateway' -Force
            Start-Sleep -Seconds 5

            $newStatus = (Get-Service -Name 'TSGateway').Status
            Write-Log "RD Gateway service status after restart: $newStatus" -Level Info

            if ($newStatus -ne 'Running') {
                throw "RD Gateway service failed to start. Status: $newStatus"
            }
        }
        else {
            Write-Log 'Service restart not requested. Changes may require a service restart to take effect.' -Level Warning
        }

        # Verify the binding
        Write-Log 'Verifying certificate binding...' -Level Info

        $boundThumbprint = $null
        if (Test-Path 'RDS:\GatewayServer\SSLCertificate') {
            $boundThumbprint = (Get-Item 'RDS:\GatewayServer\SSLCertificate\Thumbprint').CurrentValue
        }
        else {
            $tsGateway = Get-WmiObject -Namespace 'root\TSGatewayServer' -Class 'Win32_TSGatewayServerSettings'
            $boundThumbprint = $tsGateway.SSLCertificateSHA1Hash
        }

        if ($boundThumbprint -eq $certificate.Thumbprint) {
            Write-Log 'Certificate binding verified successfully' -Level Info
        }
        else {
            Write-Log "Warning: Bound thumbprint ($boundThumbprint) does not match expected ($($certificate.Thumbprint))" -Level Warning
        }
    }

    # Success
    $successMsg = "RD Gateway certificate updated successfully. Domain: $domain, Thumbprint: $($certificate.Thumbprint)"
    Write-Log $successMsg -Level Info
    Send-Event -EventType 'Installation' -Domain $domain -Thumbprint $certificate.Thumbprint -ExpiryDate $certificate.NotAfter -Message 'RD Gateway certificate binding updated' -Status 'Success'

    # Output summary
    Write-Host ''
    Write-Host '========================================' -ForegroundColor Green
    Write-Host '  RD GATEWAY CERTIFICATE UPDATED' -ForegroundColor Green
    Write-Host '========================================' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Domain:      $domain" -ForegroundColor White
    Write-Host "  Thumbprint:  $($certificate.Thumbprint)" -ForegroundColor White
    Write-Host "  Expires:     $($certificate.NotAfter)" -ForegroundColor White
    Write-Host "  Days Left:   $($validation.DaysUntilExpiry)" -ForegroundColor White
    Write-Host ''

    # Return result
    [PSCustomObject]@{
        Success = $true
        Domain = $domain
        Thumbprint = $certificate.Thumbprint
        ExpiryDate = $certificate.NotAfter
        DaysUntilExpiry = $validation.DaysUntilExpiry
        ServiceRestarted = $RestartService.IsPresent
    }
}
catch {
    $errorMsg = "Failed to update RD Gateway certificate: $($_.Exception.Message)"
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain $domain -Thumbprint $certificate.Thumbprint -Message $errorMsg -Status 'Error'
    throw
}
