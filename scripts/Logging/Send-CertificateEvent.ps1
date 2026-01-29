#Requires -Version 5.1
<#
.SYNOPSIS
    Sends certificate events to central logging destinations.

.DESCRIPTION
    This script sends certificate-related events to configured logging
    destinations including webhooks, syslog servers, and Windows Event Log.
    Used by post-renewal scripts to report success/failure.

.PARAMETER EventType
    The type of event: Renewal, Failure, Expiring, Installation, AcmeDnsRegistration.

.PARAMETER Domain
    The domain/certificate subject.

.PARAMETER Thumbprint
    The certificate thumbprint (optional).

.PARAMETER ExpiryDate
    The certificate expiry date (optional).

.PARAMETER Message
    Additional message or details about the event.

.PARAMETER Status
    The event status: Success, Warning, Error.

.PARAMETER ConfigPath
    Path to the logging configuration file.

.EXAMPLE
    .\Send-CertificateEvent.ps1 -EventType 'Renewal' -Domain 'www.example.com' -Status 'Success'

.EXAMPLE
    .\Send-CertificateEvent.ps1 -EventType 'Failure' -Domain 'mail.example.com' -Message 'DNS validation failed' -Status 'Error'

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Renewal', 'Failure', 'Expiring', 'Installation', 'AcmeDnsRegistration')]
    [string]$EventType,

    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [Parameter()]
    [string]$Thumbprint,

    [Parameter()]
    [datetime]$ExpiryDate,

    [Parameter()]
    [string]$Message,

    [Parameter()]
    [ValidateSet('Success', 'Warning', 'Error')]
    [string]$Status = 'Success',

    [Parameter()]
    [string]$ConfigPath
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

# Default config path
if (-not $ConfigPath) {
    # Check multiple locations
    $possiblePaths = @(
        (Join-Path $env:ProgramData 'WinCertManager\Config\logging-config.json'),
        (Join-Path $PSScriptRoot '..\..\config\logging-config.json'),
        (Join-Path $PSScriptRoot '..\..\config\logging-config.example.json')
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $ConfigPath = $path
            break
        }
    }
}

# Load configuration
$config = $null
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        Write-Log "Loaded logging configuration from: $ConfigPath" -Level Verbose
    }
    catch {
        Write-Log "Failed to load logging configuration: $($_.Exception.Message)" -Level Warning
    }
}

# Build event object
$hostname = $env:COMPUTERNAME
$timestamp = (Get-Date).ToString('o')

$eventData = [PSCustomObject]@{
    Timestamp = $timestamp
    Hostname = $hostname
    EventType = $EventType
    Domain = $Domain
    Thumbprint = $Thumbprint
    ExpiryDate = if ($ExpiryDate) { $ExpiryDate.ToString('o') } else { $null }
    DaysUntilExpiry = if ($ExpiryDate) { ($ExpiryDate - (Get-Date)).Days } else { $null }
    Message = $Message
    Status = $Status
    Source = 'WinCertManager'
    Version = '1.0.0'
}

$eventJson = $eventData | ConvertTo-Json -Depth 5 -Compress

Write-Log "Certificate event: $EventType for $Domain ($Status)" -Level Info

#region Windows Event Log
# Always write to Windows Event Log for local visibility
try {
    $eventSource = 'WinCertManager'
    $eventLog = 'Application'

    # Create event source if it doesn't exist
    if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource($eventSource, $eventLog)
        }
        catch {
            # May fail if not running as admin, continue anyway
            Write-Verbose "Could not create event source: $($_.Exception.Message)"
        }
    }

    # Map status to event type
    $eventEntryType = switch ($Status) {
        'Success' { [System.Diagnostics.EventLogEntryType]::Information }
        'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
        'Error'   { [System.Diagnostics.EventLogEntryType]::Error }
        default   { [System.Diagnostics.EventLogEntryType]::Information }
    }

    # Event IDs by type
    $eventId = switch ($EventType) {
        'Renewal'             { 1001 }
        'Failure'             { 2001 }
        'Expiring'            { 3001 }
        'Installation'        { 1002 }
        'AcmeDnsRegistration' { 1003 }
        default               { 1000 }
    }

    $eventMessage = @"
Certificate Event: $EventType
Domain: $Domain
Status: $Status
Hostname: $hostname
Timestamp: $timestamp
$(if ($Thumbprint) { "Thumbprint: $Thumbprint" })
$(if ($ExpiryDate) { "Expiry Date: $($ExpiryDate.ToString('yyyy-MM-dd HH:mm:ss'))" })
$(if ($Message) { "Details: $Message" })
"@

    Write-EventLog -LogName $eventLog -Source $eventSource -EventId $eventId -EntryType $eventEntryType -Message $eventMessage -ErrorAction SilentlyContinue
    Write-Log 'Event written to Windows Event Log' -Level Verbose
}
catch {
    Write-Log "Failed to write to Windows Event Log: $($_.Exception.Message)" -Level Verbose
}
#endregion

# Check if additional logging is enabled
if (-not $config -or -not $config.enabled) {
    Write-Log 'Central logging not configured or disabled' -Level Verbose
    return $eventData
}

# Ensure TLS 1.2 for web requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region Webhook
if ($config.webhook -and $config.webhook.url) {
    try {
        $webhookUrl = $config.webhook.url
        $headers = @{
            'Content-Type' = 'application/json'
        }

        # Add API key if configured
        if ($config.webhook.apiKey) {
            $headers['X-API-Key'] = $config.webhook.apiKey
        }

        # Add custom headers if configured
        if ($config.webhook.headers) {
            foreach ($header in $config.webhook.headers.PSObject.Properties) {
                $headers[$header.Name] = $header.Value
            }
        }

        Write-Log "Sending event to webhook: $webhookUrl" -Level Verbose

        $null = Invoke-RestMethod -Uri $webhookUrl -Method Post -Headers $headers -Body $eventJson -TimeoutSec 30 -UseBasicParsing

        Write-Log 'Webhook notification sent successfully' -Level Verbose
    }
    catch {
        Write-Log "Failed to send webhook notification: $($_.Exception.Message)" -Level Warning
    }
}
#endregion

#region Syslog
if ($config.syslog -and $config.syslog.server) {
    try {
        $syslogServer = $config.syslog.server
        $syslogPort = if ($config.syslog.port) { $config.syslog.port } else { 514 }
        $syslogProtocol = if ($config.syslog.protocol) { $config.syslog.protocol.ToUpper() } else { 'UDP' }

        # Build syslog message (RFC 5424 format)
        $facility = 16  # local0
        $severity = switch ($Status) {
            'Success' { 6 }  # Informational
            'Warning' { 4 }  # Warning
            'Error'   { 3 }  # Error
            default   { 6 }
        }
        $priority = ($facility * 8) + $severity

        $syslogMessage = "<$priority>1 $timestamp $hostname WinCertManager - - - ${EventType}: ${Domain} - ${Status}"
        if ($Message) {
            $syslogMessage += " - $Message"
        }

        Write-Log "Sending event to syslog: ${syslogServer}:$syslogPort ($syslogProtocol)" -Level Verbose

        switch ($syslogProtocol) {
            'UDP' {
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($syslogMessage)
                $udpClient.Send($bytes, $bytes.Length, $syslogServer, $syslogPort) | Out-Null
                $udpClient.Close()
            }
            'TCP' {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($syslogServer, $syslogPort)
                $stream = $tcpClient.GetStream()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes("$syslogMessage`n")
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Close()
                $tcpClient.Close()
            }
        }

        Write-Log 'Syslog notification sent successfully' -Level Verbose
    }
    catch {
        Write-Log "Failed to send syslog notification: $($_.Exception.Message)" -Level Warning
    }
}
#endregion

# Return event data for pipeline usage
$eventData
