
#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Enroll custom Secure Boot keys from Setup Mode.

.DESCRIPTION
    Uses native Windows SecureBoot cmdlets.

    Installation order:
      1. db
      2. dbx
      3. KEK
      4. PK

    DB and KEK are replaced.
    DBX is appended to preserve existing revocations.
    PK is installed last.

    Does not use OpenSSL, Python or efitools.

.NOTES
    Run only after verifying Setup Mode.
    Keep firmware recovery access available.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$OutputDirectory = ".\data",
    [string]$KekDirectory = ".\KEK-export",
    [string]$DbxFile = ".\dbx.txt",

    # Optional: enroll the previously generated shim hash.
    # Only use after independently validating its PE/COFF hash.
    [switch]$IncludeShimHash
)

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$Root = (Get-Location).Path

$OutputDirectory = [IO.Path]::GetFullPath(
    (Join-Path $Root $OutputDirectory)
)

$KekDirectory = [IO.Path]::GetFullPath(
    (Join-Path $Root $KekDirectory)
)

$DbxFile = [IO.Path]::GetFullPath(
    (Join-Path $Root $DbxFile)
)

$GuidFile = Join-Path $Root "GUID.txt"

$timestamp = [DateTime]::UtcNow.ToString(
    "yyyy-MM-ddTHH:mm:ssZ"
)

# ============================================================
# HELPERS
# ============================================================

function Write-Section {
    param([string]$Message)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
}

function Assert-File {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }
}

function Get-CertificateFiles {

    Write-Section "COLLECTING DB CERTIFICATES"

    $files = @()

    $dbCertificate = Join-Path $OutputDirectory "db.cer"
    Assert-File $dbCertificate

    $files += $dbCertificate

    if (Test-Path $KekDirectory) {

        $currentKek = @(
            Get-ChildItem -LiteralPath $KekDirectory `
                -Filter "current_kek-*.der" -File
        )

        foreach ($file in $currentKek) {
            $files += $file.FullName
        }
    }

    $suse = Join-Path $Root `
        "soliddriver-UEFI-SIGN-Certificate.crt"

    if (Test-Path $suse) {
        $files += $suse
    }

    foreach ($file in $files) {

        $cert = Import-CertificateForValidation $file

        try {
            Write-Host "$file"
            Write-Host "  $($cert.Subject)"
        }
        finally {
            $cert.Dispose()
        }
    }

    return $files
}

function Import-CertificateForValidation {

    param([string]$Path)

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)

    $text = [Text.Encoding]::ASCII.GetString($bytes)

    if ($text -match "-----BEGIN CERTIFICATE-----") {

        $base64 = $text -replace "-----BEGIN CERTIFICATE-----", ""
        $base64 = $base64 -replace "-----END CERTIFICATE-----", ""
        $base64 = $base64 -replace "\s", ""

        $bytes = [Convert]::FromBase64String($base64)
    }

    return [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $bytes
    )
}

function Get-DbxHashes {

    Assert-File $DbxFile

    $content = Get-Content -LiteralPath $DbxFile -Raw

    $hashes = @(
        [regex]::Matches(
            $content,
            '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])'
        ) |
        ForEach-Object {
            $_.Value.ToUpperInvariant()
        } |
        Select-Object -Unique
    )

    if ($hashes.Count -eq 0) {
        throw "dbx.txt contains no SHA256 hashes. Nothing will be installed."
    }

    return $hashes
}

function Get-ShimHashFromEsl {

    $path = Join-Path $OutputDirectory "shim_hash.esl"

    Assert-File $path

    [byte[]]$bytes = [IO.File]::ReadAllBytes($path)

    if ($bytes.Length -lt 76) {
        throw "Invalid shim_hash.esl."
    }

    $guid = [Guid]::new(
        [byte[]]$bytes[0..15]
    )

    if ($guid -ne [Guid]"c1c41626-504c-4092-aca9-41f936934328") {
        throw "shim_hash.esl does not contain a SHA256 signature list."
    }

    $listSize = [BitConverter]::ToUInt32($bytes, 16)
    $headerSize = [BitConverter]::ToUInt32($bytes, 20)
    $signatureSize = [BitConverter]::ToUInt32($bytes, 24)

    if ($listSize -ne $bytes.Length -or
        $headerSize -ne 0 -or
        $signatureSize -ne 48) {

        throw "Unexpected shim ESL structure."
    }

    $hashes = @()

    for ($offset = 28; $offset -lt $listSize; $offset += 48) {

        $hash = [BitConverter]::ToString(
            $bytes,
            $offset + 16,
            32
        ).Replace("-", "")

        $hashes += $hash
    }

    if ($hashes.Count -eq 0) {
        throw "No shim hashes found."
    }

    return $hashes
}

function Save-VariableBackup {

    param(
        [string]$Name,
        [string]$BackupDirectory
    )

    try {

        $variable = Get-SecureBootUEFI -Name $Name `
            -ErrorAction Stop

        $path = Join-Path $BackupDirectory "$Name.bin"

        [IO.File]::WriteAllBytes(
            $path,
            [byte[]]$variable.Bytes
        )

        Write-Host "Saved $Name variable snapshot."
    }
    catch {
        Write-Warning "Could not snapshot $Name : $_"
    }
}

function Install-FormattedVariable {

    param(
        [string]$Name,
        [object]$FormattedVariable
    )

    Write-Host ""
    Write-Host "Installing $Name..." -ForegroundColor Yellow

    $result = $FormattedVariable | Set-SecureBootUEFI `
        -ErrorAction Stop

    if (-not $result) {
        throw "Firmware did not confirm installation of $Name."
    }

    Write-Host "$Name installation command completed." `
        -ForegroundColor Green

    return $result
}

# ============================================================
# INITIAL VALIDATION
# ============================================================

Write-Section "SECURE BOOT COMMIT"

Import-Module SecureBoot -ErrorAction Stop

if (-not (Get-Command Format-SecureBootUEFI -ErrorAction SilentlyContinue)) {
    throw "Format-SecureBootUEFI is unavailable."
}

if (-not (Get-Command Set-SecureBootUEFI -ErrorAction SilentlyContinue)) {
    throw "Set-SecureBootUEFI is unavailable."
}

Assert-File $GuidFile

$ProjectGuid = [Guid]::Parse(
    (Get-Content $GuidFile -Raw).Trim()
)

Write-Host "Project GUID: $ProjectGuid"

# ============================================================
# VERIFY SETUP MODE
# ============================================================

Write-Section "VERIFYING SETUP MODE"

$setup = Get-SecureBootUEFI -Name SetupMode

if ($setup.Bytes.Length -lt 1) {
    throw "Cannot determine SetupMode."
}

if ($setup.Bytes[0] -ne 1) {
    throw "System is NOT in Setup Mode. No changes made."
}

Write-Host "Setup Mode confirmed." -ForegroundColor Green

# ============================================================
# VALIDATE ALL INPUTS BEFORE WRITING
# ============================================================

Write-Section "VALIDATING INPUT FILES"

$pkCertificate = Join-Path $OutputDirectory "PK.cer"
$kekCertificate = Join-Path $OutputDirectory "KEK.cer"

Assert-File $pkCertificate
Assert-File $kekCertificate

$dbCertificates = @(Get-CertificateFiles)

$dbxHashes = @(Get-DbxHashes)

$shimHashes = @()

if ($IncludeShimHash) {

    Write-Warning "Shim hash enrollment explicitly enabled."

    $shimHashes = @(Get-ShimHashFromEsl)
}

Write-Host ""
Write-Host "DB certificates: $($dbCertificates.Count)"
Write-Host "DBX hashes: $($dbxHashes.Count)"
Write-Host "Shim hashes: $($shimHashes.Count)"

# ============================================================
# BACKUP CURRENT VARIABLES
# ============================================================

Write-Section "BACKING UP CURRENT VARIABLES"

$BackupDirectory = Join-Path $OutputDirectory (
    "firmware-backup-" +
    (Get-Date -Format "yyyyMMdd-HHmmss")
)

New-Item -ItemType Directory -Force `
    -Path $BackupDirectory | Out-Null

foreach ($name in @("PK", "KEK", "db", "dbx")) {

    Save-VariableBackup `
        -Name $name `
        -BackupDirectory $BackupDirectory
}

Write-Host ""
Write-Host "Variable snapshots: $BackupDirectory"

Write-Warning "These snapshots are for inspection, not guaranteed firmware recovery packages."

# ============================================================
# CONFIRM DESTRUCTIVE OPERATION
# ============================================================

Write-Section "ENROLLMENT CONFIRMATION"

Write-Host "The following operations will occur:"
Write-Host "  1. Replace db"
Write-Host "  2. Append dbx revocations"
Write-Host "  3. Replace KEK"
Write-Host "  4. Install PK LAST"

Write-Host ""
Write-Host "Installing PK will normally leave Setup Mode."

$confirmation = Read-Host `
    "Type INSTALL to proceed"

if ($confirmation -cne "INSTALL") {
    throw "Installation cancelled. No firmware variables changed."
}

# ============================================================
# 1. INSTALL DB
# ============================================================

Write-Section "INSTALLING DB"

$dbFormatted = Format-SecureBootUEFI `
    -Name db `
    -SignatureOwner $ProjectGuid `
    -CertificateFilePath $dbCertificates `
    -FormatWithCert `
    -Time $timestamp `
    -ErrorAction Stop

if ($PSCmdlet.ShouldProcess("UEFI db", "Replace trusted certificates")) {

    Install-FormattedVariable `
        -Name db `
        -FormattedVariable $dbFormatted
}

# ------------------------------------------------------------
# Optional shim hash: append to DB

if ($IncludeShimHash -and $shimHashes.Count -gt 0) {

    Write-Section "APPENDING SHIM HASH"

    $shimFormatted = Format-SecureBootUEFI `
        -Name db `
        -SignatureOwner $ProjectGuid `
        -Algorithm SHA256 `
        -Hash $shimHashes `
        -AppendWrite `
        -Time $timestamp `
        -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess("UEFI db", "Append shim hash")) {

        Install-FormattedVariable `
            -Name db `
            -FormattedVariable $shimFormatted
    }
}

# ============================================================
# 2. INSTALL DBX
# ============================================================

Write-Section "INSTALLING DBX"

$dbxFormatted = Format-SecureBootUEFI `
    -Name dbx `
    -SignatureOwner $ProjectGuid `
    -Algorithm SHA256 `
    -Hash $dbxHashes `
    -AppendWrite `
    -Time $timestamp `
    -ErrorAction Stop

if ($PSCmdlet.ShouldProcess("UEFI dbx", "Append revocation hashes")) {

    Install-FormattedVariable `
        -Name dbx `
        -FormattedVariable $dbxFormatted
}

# ============================================================
# 3. INSTALL KEK
# ============================================================

Write-Section "INSTALLING KEK"

$kekFormatted = Format-SecureBootUEFI `
    -Name KEK `
    -SignatureOwner $ProjectGuid `
    -CertificateFilePath $kekCertificate `
    -FormatWithCert `
    -Time $timestamp `
    -ErrorAction Stop

if ($PSCmdlet.ShouldProcess("UEFI KEK", "Replace key exchange keys")) {

    Install-FormattedVariable `
        -Name KEK `
        -FormattedVariable $kekFormatted
}

# ============================================================
# 4. INSTALL PK LAST
# ============================================================

Write-Section "INSTALLING PLATFORM KEY"

$pkFormatted = Format-SecureBootUEFI `
    -Name PK `
    -SignatureOwner $ProjectGuid `
    -CertificateFilePath $pkCertificate `
    -FormatWithCert `
    -Time $timestamp `
    -ErrorAction Stop

if ($PSCmdlet.ShouldProcess("UEFI PK", "Enroll platform key")) {

    Install-FormattedVariable `
        -Name PK `
        -FormattedVariable $pkFormatted
}

# ============================================================
# FINAL REPORT
# ============================================================

Write-Section "COMMIT COMPLETED"

Write-Host "Enrollment commands completed." -ForegroundColor Green

Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "1. Reboot the computer."
Write-Host "2. Enter firmware setup."
Write-Host "3. Verify Secure Boot mode."
Write-Host "4. Verify that PK, KEK, db and dbx are populated."

Write-Host ""
Write-Host "The firmware may require a reboot to finalize the mode transition."
