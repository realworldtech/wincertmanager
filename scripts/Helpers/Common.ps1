#Requires -Version 5.1
<#
.SYNOPSIS
    Common helper functions for Windows Certificate Manager Toolkit.

.DESCRIPTION
    Shared functions used across all scripts in the toolkit including logging,
    certificate operations, and utility functions.

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

# Script-level variables
$script:LogPath = Join-Path $env:ProgramData 'WinCertManager\Logs'
$script:ConfigPath = Join-Path $env:ProgramData 'WinCertManager\Config'
$script:LoggingErrors = @()  # Track logging failures for diagnostic purposes

function Initialize-WinCertManager {
    <#
    .SYNOPSIS
        Initializes the WinCertManager environment.

    .DESCRIPTION
        Creates necessary directories and sets up logging.
    #>
    [CmdletBinding()]
    param()

    # Create directories if they don't exist
    $directories = @(
        $script:LogPath,
        $script:ConfigPath,
        (Join-Path $script:ConfigPath 'acme-dns')
    )

    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Verbose "Created directory: $dir"
        }
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry to file and optionally to console.

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        The log level (Info, Warning, Error, Verbose).

    .PARAMETER LogFile
        Optional specific log file name. Defaults to daily log.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '',
        Justification = 'Write-Log is not a built-in cmdlet in Windows PowerShell 5.1 which this targets')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose')]
        [string]$Level = 'Info',

        [Parameter()]
        [string]$LogFile
    )

    Initialize-WinCertManager

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Determine log file path
    if (-not $LogFile) {
        $LogFile = "wincertmanager-$(Get-Date -Format 'yyyy-MM-dd').log"
    }
    $logFilePath = Join-Path $script:LogPath $LogFile

    # Write to log file with error tracking
    try {
        Add-Content -Path $logFilePath -Value $logEntry -ErrorAction Stop
    }
    catch {
        # Track the logging failure for diagnostics
        $loggingError = [PSCustomObject]@{
            Timestamp = $timestamp
            Target = 'LogFile'
            Path = $logFilePath
            Error = $_.Exception.Message
        }
        $script:LoggingErrors += $loggingError

        # Attempt to write to console as fallback
        Write-Verbose "Could not write to log file '$logFilePath': $($_.Exception.Message)"
    }

    # Write to console based on level
    switch ($Level) {
        'Error'   { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Verbose' { Write-Verbose $Message }
        default   { Write-Host $Message }
    }

    # Also write to Windows Event Log for important events
    if ($Level -in @('Error', 'Warning')) {
        $eventType = if ($Level -eq 'Error') { 'Error' } else { 'Warning' }
        try {
            # Create event source if it doesn't exist
            if (-not [System.Diagnostics.EventLog]::SourceExists('WinCertManager')) {
                [System.Diagnostics.EventLog]::CreateEventSource('WinCertManager', 'Application')
            }
            Write-EventLog -LogName Application -Source 'WinCertManager' -EventId 1000 -EntryType $eventType -Message $Message -ErrorAction Stop
        }
        catch {
            # Track the event log failure for diagnostics
            $loggingError = [PSCustomObject]@{
                Timestamp = $timestamp
                Target = 'EventLog'
                Path = 'Application'
                Error = $_.Exception.Message
            }
            $script:LoggingErrors += $loggingError
            Write-Verbose "Could not write to event log: $($_.Exception.Message)"
        }
    }
}

function Get-OSVersion {
    <#
    .SYNOPSIS
        Gets the Windows Server version information.

    .OUTPUTS
        PSCustomObject with Version, Name, and BuildNumber properties.
    #>
    [CmdletBinding()]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $version = [System.Environment]::OSVersion.Version

    $versionName = switch -Regex ($os.Caption) {
        '2012 R2' { 'Server2012R2' }
        '2012'    { 'Server2012' }
        '2016'    { 'Server2016' }
        '2019'    { 'Server2019' }
        '2022'    { 'Server2022' }
        '2025'    { 'Server2025' }
        default   { 'Unknown' }
    }

    [PSCustomObject]@{
        Version     = $version
        Name        = $versionName
        Caption     = $os.Caption
        BuildNumber = $os.BuildNumber
        Is2012      = $versionName -in @('Server2012', 'Server2012R2')
    }
}

function Test-TLS12Enabled {
    <#
    .SYNOPSIS
        Tests if TLS 1.2 is enabled on the system.

    .OUTPUTS
        Boolean indicating if TLS 1.2 is properly configured.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $serverPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'

    $clientEnabled = $false
    $serverEnabled = $false

    # Check client
    if (Test-Path $clientPath) {
        $clientSettings = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
        $clientEnabled = ($clientSettings.Enabled -eq 1) -or ($null -eq $clientSettings.Enabled -and $clientSettings.DisabledByDefault -ne 1)
    }

    # Check server
    if (Test-Path $serverPath) {
        $serverSettings = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
        $serverEnabled = ($serverSettings.Enabled -eq 1) -or ($null -eq $serverSettings.Enabled -and $serverSettings.DisabledByDefault -ne 1)
    }

    # On newer systems, TLS 1.2 is enabled by default even without registry keys
    $osVersion = Get-OSVersion
    if (-not $osVersion.Is2012) {
        return $true
    }

    return $clientEnabled -and $serverEnabled
}

function Enable-TLS12 {
    <#
    .SYNOPSIS
        Enables TLS 1.2 via registry settings.

    .DESCRIPTION
        Creates necessary registry keys to enable TLS 1.2 on older Windows versions.
        A reboot is required for changes to take effect.

    .PARAMETER WhatIf
        Shows what would happen without making changes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $protocols = @(
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            Settings = @{
                Enabled = 1
                DisabledByDefault = 0
            }
        },
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Settings = @{
                Enabled = 1
                DisabledByDefault = 0
            }
        }
    )

    foreach ($protocol in $protocols) {
        if ($PSCmdlet.ShouldProcess($protocol.Path, 'Enable TLS 1.2')) {
            # Create path if it doesn't exist
            if (-not (Test-Path $protocol.Path)) {
                New-Item -Path $protocol.Path -Force | Out-Null
            }

            # Set values
            foreach ($setting in $protocol.Settings.GetEnumerator()) {
                Set-ItemProperty -Path $protocol.Path -Name $setting.Key -Value $setting.Value -Type DWord
            }
        }
    }

    # Also ensure .NET uses strong crypto
    $netFrameworkPaths = @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )

    foreach ($path in $netFrameworkPaths) {
        if (Test-Path $path) {
            if ($PSCmdlet.ShouldProcess($path, 'Enable Strong Crypto')) {
                Set-ItemProperty -Path $path -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
            }
        }
    }

    Write-Log 'TLS 1.2 registry settings configured. A reboot is required for changes to take effect.' -Level Warning
}

function Get-DotNetVersion {
    <#
    .SYNOPSIS
        Gets the installed .NET Framework version.

    .OUTPUTS
        PSCustomObject with Version and Release properties.
    #>
    [CmdletBinding()]
    param()

    $ndpPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'

    if (-not (Test-Path $ndpPath)) {
        return [PSCustomObject]@{
            Version = $null
            Release = 0
            Installed = $false
        }
    }

    $release = (Get-ItemProperty -Path $ndpPath -Name Release -ErrorAction SilentlyContinue).Release

    # Map release number to version
    $version = switch ($release) {
        { $_ -ge 533320 } { '4.8.1' }
        { $_ -ge 528040 } { '4.8' }
        { $_ -ge 461808 } { '4.7.2' }
        { $_ -ge 461308 } { '4.7.1' }
        { $_ -ge 460798 } { '4.7' }
        { $_ -ge 394802 } { '4.6.2' }
        { $_ -ge 394254 } { '4.6.1' }
        { $_ -ge 393295 } { '4.6' }
        { $_ -ge 379893 } { '4.5.2' }
        { $_ -ge 378675 } { '4.5.1' }
        { $_ -ge 378389 } { '4.5' }
        default { 'Unknown' }
    }

    [PSCustomObject]@{
        Version = $version
        Release = $release
        Installed = $true
        MeetsMinimum = $release -ge 461808  # 4.7.2
    }
}

function Get-CertificateByThumbprint {
    <#
    .SYNOPSIS
        Finds a certificate by thumbprint in the certificate store.

    .PARAMETER Thumbprint
        The certificate thumbprint to search for.

    .PARAMETER StoreName
        The store name to search (default: My).

    .PARAMETER StoreLocation
        The store location (default: LocalMachine).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter()]
        [string]$StoreName = 'My',

        [Parameter()]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation = 'LocalMachine'
    )

    $certPath = "Cert:\$StoreLocation\$StoreName\$Thumbprint"

    if (Test-Path $certPath) {
        return Get-Item $certPath
    }

    return $null
}

function Get-CertificateBySubject {
    <#
    .SYNOPSIS
        Finds certificates by subject name in the certificate store.

    .PARAMETER Subject
        The subject name to search for (partial match).

    .PARAMETER StoreName
        The store name to search (default: My).

    .PARAMETER StoreLocation
        The store location (default: LocalMachine).

    .PARAMETER Latest
        If specified, returns only the most recent certificate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter()]
        [string]$StoreName = 'My',

        [Parameter()]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation = 'LocalMachine',

        [Parameter()]
        [switch]$Latest
    )

    $storePath = "Cert:\$StoreLocation\$StoreName"
    $certs = Get-ChildItem -Path $storePath | Where-Object { $_.Subject -like "*$Subject*" }

    if ($Latest -and $certs) {
        return $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
    }

    return $certs
}

function Test-CertificateValid {
    <#
    .SYNOPSIS
        Tests if a certificate is valid (not expired, has private key).

    .PARAMETER Certificate
        The certificate object to test.

    .PARAMETER RequirePrivateKey
        If specified, requires the certificate to have a private key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [switch]$RequirePrivateKey
    )

    $now = Get-Date

    $isValid = $true
    $issues = @()

    # Check validity period
    if ($now -lt $Certificate.NotBefore) {
        $isValid = $false
        $issues += "Certificate is not yet valid (NotBefore: $($Certificate.NotBefore))"
    }

    if ($now -gt $Certificate.NotAfter) {
        $isValid = $false
        $issues += "Certificate has expired (NotAfter: $($Certificate.NotAfter))"
    }

    # Check private key
    if ($RequirePrivateKey -and -not $Certificate.HasPrivateKey) {
        $isValid = $false
        $issues += 'Certificate does not have a private key'
    }

    [PSCustomObject]@{
        IsValid = $isValid
        Issues = $issues
        DaysUntilExpiry = ($Certificate.NotAfter - $now).Days
        Thumbprint = $Certificate.Thumbprint
        Subject = $Certificate.Subject
    }
}

function Get-WinAcmePath {
    <#
    .SYNOPSIS
        Gets the win-acme installation path.

    .OUTPUTS
        The path to win-acme installation or $null if not found.
    #>
    [CmdletBinding()]
    param()

    $possiblePaths = @(
        'C:\Tools\win-acme',
        'C:\Program Files\win-acme',
        "$env:ProgramFiles\win-acme",
        "$env:LOCALAPPDATA\win-acme"
    )

    foreach ($path in $possiblePaths) {
        $wacs = Join-Path $path 'wacs.exe'
        if (Test-Path $wacs) {
            return $path
        }
    }

    return $null
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Tests if the current session has administrator privileges.
    #>
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Invokes a script block with retry logic.

    .PARAMETER ScriptBlock
        The script block to execute.

    .PARAMETER MaxRetries
        Maximum number of retry attempts.

    .PARAMETER DelaySeconds
        Delay between retries in seconds.

    .PARAMETER Description
        Description for logging purposes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$MaxRetries = 3,

        [Parameter()]
        [int]$DelaySeconds = 5,

        [Parameter()]
        [string]$Description = 'Operation'
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $result = & $ScriptBlock
            return $result
        }
        catch {
            $lastError = $_
            Write-Log "$Description failed (attempt $attempt of $MaxRetries): $($_.Exception.Message)" -Level Warning

            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    Write-Log "$Description failed after $MaxRetries attempts: $($lastError.Exception.Message)" -Level Error
    throw $lastError
}

function ConvertTo-SecureCredential {
    <#
    .SYNOPSIS
        Converts a plain text password to a secure string.

    .DESCRIPTION
        This function is used for DPAPI encryption where the plaintext
        is immediately encrypted and stored. The plaintext is not logged
        or persisted in an insecure manner.

    .PARAMETER PlainText
        The plain text to convert.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Required for DPAPI encryption of credentials received from API')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText
    )

    return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
}

function Get-SecureCredentialFile {
    <#
    .SYNOPSIS
        Gets the path to a secure credential file.

    .PARAMETER Name
        The name of the credential file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Initialize-WinCertManager
    return Join-Path (Join-Path $script:ConfigPath 'acme-dns') "$Name.json"
}

function Get-LoggingErrors {
    <#
    .SYNOPSIS
        Retrieves any logging errors that occurred during the session.

    .DESCRIPTION
        Returns a collection of logging errors that were suppressed during operation.
        This helps administrators diagnose issues with file or event log permissions.

    .PARAMETER Clear
        If specified, clears the error collection after returning.

    .EXAMPLE
        Get-LoggingErrors
        Returns all logging errors from the current session.

    .EXAMPLE
        Get-LoggingErrors -Clear
        Returns all logging errors and clears the collection.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Function returns a collection of errors')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '',
        Justification = 'Returns PSCustomObject[] or empty array')]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [switch]$Clear
    )

    $errors = $script:LoggingErrors

    if ($Clear) {
        $script:LoggingErrors = @()
    }

    if ($errors.Count -eq 0) {
        Write-Verbose 'No logging errors recorded'
        return @()
    }

    Write-Warning "$($errors.Count) logging error(s) occurred during this session"
    return $errors
}

#region Windows Credential Manager Functions
# P/Invoke definitions for Windows Credential Manager API
# This avoids using cmdkey which exposes credentials on the command line

$script:CredentialManagerTypeAdded = $false

function Initialize-CredentialManager {
    <#
    .SYNOPSIS
        Initializes the Credential Manager P/Invoke types.

    .DESCRIPTION
        Adds the necessary .NET types for interacting with Windows Credential Manager
        via the advapi32.dll CredWrite and CredRead functions.
    #>
    [CmdletBinding()]
    param()

    if ($script:CredentialManagerTypeAdded) {
        return
    }

    $credManagerCode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WinCertManager
{
    public enum CredentialType : uint
    {
        Generic = 1,
        DomainPassword = 2,
        DomainCertificate = 3,
        DomainVisiblePassword = 4,
        GenericCertificate = 5,
        DomainExtended = 6,
        Maximum = 7,
        MaximumEx = (Maximum + 1000)
    }

    public enum CredentialPersist : uint
    {
        Session = 1,
        LocalMachine = 2,
        Enterprise = 3
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NativeCredential
    {
        public uint Flags;
        public CredentialType Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public CredentialPersist Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    public class CredentialManager
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredWriteW(ref NativeCredential credential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredReadW(string target, CredentialType type, uint reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CredDeleteW(string target, CredentialType type, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr buffer);

        public static bool WriteCredential(string target, string username, string password)
        {
            byte[] passwordBytes = Encoding.Unicode.GetBytes(password);

            NativeCredential cred = new NativeCredential();
            cred.Type = CredentialType.Generic;
            cred.TargetName = Marshal.StringToCoTaskMemUni(target);
            cred.UserName = Marshal.StringToCoTaskMemUni(username);
            cred.CredentialBlobSize = (uint)passwordBytes.Length;
            cred.CredentialBlob = Marshal.AllocCoTaskMem(passwordBytes.Length);
            Marshal.Copy(passwordBytes, 0, cred.CredentialBlob, passwordBytes.Length);
            cred.Persist = CredentialPersist.LocalMachine;

            bool result = false;
            try
            {
                result = CredWriteW(ref cred, 0);
            }
            finally
            {
                Marshal.FreeCoTaskMem(cred.TargetName);
                Marshal.FreeCoTaskMem(cred.UserName);
                // Securely clear the password from memory
                Marshal.Copy(new byte[passwordBytes.Length], 0, cred.CredentialBlob, passwordBytes.Length);
                Marshal.FreeCoTaskMem(cred.CredentialBlob);
            }

            return result;
        }

        public static bool DeleteCredential(string target)
        {
            return CredDeleteW(target, CredentialType.Generic, 0);
        }

        public static string[] ReadCredential(string target)
        {
            IntPtr credPtr;
            if (!CredReadW(target, CredentialType.Generic, 0, out credPtr))
            {
                return null;
            }

            try
            {
                NativeCredential cred = (NativeCredential)Marshal.PtrToStructure(credPtr, typeof(NativeCredential));
                string username = Marshal.PtrToStringUni(cred.UserName);
                string password = null;

                if (cred.CredentialBlobSize > 0)
                {
                    password = Marshal.PtrToStringUni(cred.CredentialBlob, (int)cred.CredentialBlobSize / 2);
                }

                return new string[] { username, password };
            }
            finally
            {
                CredFree(credPtr);
            }
        }

        public static bool CredentialExists(string target)
        {
            IntPtr credPtr;
            if (CredReadW(target, CredentialType.Generic, 0, out credPtr))
            {
                CredFree(credPtr);
                return true;
            }
            return false;
        }
    }
}
'@

    try {
        Add-Type -TypeDefinition $credManagerCode -Language CSharp -ErrorAction Stop
        $script:CredentialManagerTypeAdded = $true
    }
    catch {
        if ($_.Exception.Message -notmatch 'already exists') {
            throw
        }
        $script:CredentialManagerTypeAdded = $true
    }
}

function Set-WindowsCredential {
    <#
    .SYNOPSIS
        Stores a credential in Windows Credential Manager securely.

    .DESCRIPTION
        Uses the Windows Credential Manager API via P/Invoke to store credentials
        without exposing them on the command line. This is more secure than using
        cmdkey.exe which passes credentials as command-line arguments.

    .PARAMETER Target
        The target name (identifier) for the credential.

    .PARAMETER Username
        The username to store.

    .PARAMETER SecurePassword
        The password as a SecureString.

    .PARAMETER WhatIf
        Shows what would happen without making changes.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .EXAMPLE
        $secPwd = ConvertTo-SecureString "password" -AsPlainText -Force
        Set-WindowsCredential -Target "acme-dns:example.com" -Username "user" -SecurePassword $secPwd
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecurePassword
    )

    Initialize-CredentialManager

    if (-not $PSCmdlet.ShouldProcess($Target, 'Store credential in Windows Credential Manager')) {
        return $false
    }

    # Convert SecureString to plain text for the API call
    # The C# code will securely clear this from memory after use
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    try {
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $result = [WinCertManager.CredentialManager]::WriteCredential($Target, $Username, $password)

        if (-not $result) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log "Failed to write credential to Credential Manager. Error code: $errorCode" -Level Error
        }

        return $result
    }
    finally {
        # Securely clear the BSTR
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-WindowsCredential {
    <#
    .SYNOPSIS
        Retrieves a credential from Windows Credential Manager.

    .DESCRIPTION
        Uses the Windows Credential Manager API via P/Invoke to retrieve credentials.

    .PARAMETER Target
        The target name (identifier) for the credential.

    .PARAMETER AsPlainText
        If specified, returns the password as plain text. Use with caution.

    .OUTPUTS
        PSCredential object, or PSCustomObject with Username and Password if AsPlainText is specified.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Password is retrieved from secure Credential Manager API and converted to SecureString for PSCredential')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter()]
        [switch]$AsPlainText
    )

    Initialize-CredentialManager

    $result = [WinCertManager.CredentialManager]::ReadCredential($Target)

    if ($null -eq $result) {
        return $null
    }

    $username = $result[0]
    $password = $result[1]

    if ($AsPlainText) {
        Write-Log "Credential retrieved as plain text for target: $Target" -Level Warning
        return [PSCustomObject]@{
            Username = $username
            Password = $password
        }
    }

    # Return as PSCredential with SecureString password
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($username, $securePassword)
}

function Remove-WindowsCredential {
    <#
    .SYNOPSIS
        Removes a credential from Windows Credential Manager.

    .PARAMETER Target
        The target name (identifier) for the credential to remove.

    .PARAMETER WhatIf
        Shows what would happen without making changes.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Initialize-CredentialManager

    if (-not $PSCmdlet.ShouldProcess($Target, 'Remove credential from Windows Credential Manager')) {
        return $false
    }

    return [WinCertManager.CredentialManager]::DeleteCredential($Target)
}

function Test-WindowsCredentialExists {
    <#
    .SYNOPSIS
        Tests if a credential exists in Windows Credential Manager.

    .PARAMETER Target
        The target name (identifier) to check.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Exists is a standard verb pattern, not a plural noun')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Initialize-CredentialManager

    return [WinCertManager.CredentialManager]::CredentialExists($Target)
}
#endregion

# Export functions
Export-ModuleMember -Function @(
    'Initialize-WinCertManager',
    'Write-Log',
    'Get-LoggingErrors',
    'Get-OSVersion',
    'Test-TLS12Enabled',
    'Enable-TLS12',
    'Get-DotNetVersion',
    'Get-CertificateByThumbprint',
    'Get-CertificateBySubject',
    'Test-CertificateValid',
    'Get-WinAcmePath',
    'Test-IsAdministrator',
    'Invoke-WithRetry',
    'ConvertTo-SecureCredential',
    'Get-SecureCredentialFile',
    'Initialize-CredentialManager',
    'Set-WindowsCredential',
    'Get-WindowsCredential',
    'Remove-WindowsCredential',
    'Test-WindowsCredentialExists'
)
