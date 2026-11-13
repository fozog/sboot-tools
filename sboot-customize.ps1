
#requires -Version 5.1

<#
    Build-SecureBoot.ps1

    Native Windows PowerShell 5.1
    No OpenSSL, Python or efitools.

    Part 1: Initialization and core functions.
#>

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# CONFIGURATION

$Root = (Get-Location).Path

$KekDirectory = Join-Path $Root "KEK-export"
$KeyDirectory = Join-Path $Root "keys"
$OutputDirectory = Join-Path $Root "data"

$SuseCertificate = Join-Path $Root `
    "soliddriver-UEFI-SIGN-Certificate.crt"

$DbxFile = Join-Path $Root "dbx.txt"
$GuidFile = Join-Path $Root "GUID.txt"

$X509Guid = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
$Sha256Guid = [Guid]"c1c41626-504c-4092-aca9-41f936934328"

$EspGuid = "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"

New-Item -ItemType Directory -Force -Path $KeyDirectory |
    Out-Null

New-Item -ItemType Directory -Force -Path $OutputDirectory |
    Out-Null

# ------------------------------------------------------------
# ADMINISTRATOR CHECK

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

$IsAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdmin) {
    Write-Warning "Run PowerShell as Administrator for ESP discovery."
}

# ------------------------------------------------------------
# PROJECT GUID

if (-not (Test-Path $GuidFile)) {
    [Guid]::NewGuid().ToString() |
        Set-Content -Path $GuidFile -NoNewline
}

$ProjectGuid = [Guid]::Parse(
    (Get-Content $GuidFile -Raw).Trim()
)

Write-Host "Project GUID: $ProjectGuid" -ForegroundColor Cyan

# ------------------------------------------------------------
# GENERAL HELPERS

function Write-Section {
    param([string]$Message)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
}

function Write-Binary {
    param(
        [string]$Path,
        [byte[]]$Bytes
    )

    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Join-BinaryFiles {
    param(
        [string[]]$Files,
        [string]$Output
    )

    $stream = New-Object IO.MemoryStream

    try {
        foreach ($file in $Files) {

            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
                throw "File not found: $file"
            }

            [byte[]]$bytes = [IO.File]::ReadAllBytes($file)

            $stream.Write($bytes, 0, $bytes.Length)
        }

        Write-Binary $Output $stream.ToArray()
    }
    finally {
        $stream.Dispose()
    }
}

# ------------------------------------------------------------
# CERTIFICATE GENERATION

function New-SecureBootCertificate {

    param(
        [string]$CommonName,
        [string]$PfxPath,
        [string]$DerPath,
        [string]$Password
    )

    $rsa = New-Object System.Security.Cryptography.RSACng -ArgumentList 2048
    $rsa.KeySize = 2048

    try {

        $subject = New-Object `
            Security.Cryptography.X509Certificates.X500DistinguishedName(
                "CN=$CommonName"
            )

        $request = New-Object `
            Security.Cryptography.X509Certificates.CertificateRequest(
                $subject,
                $rsa,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )

        $usage = New-Object `
            Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
                $false
            )

        $request.CertificateExtensions.Add($usage)

        $basic = New-Object `
            Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(
                $false, $false, 0, $true
            )

        $request.CertificateExtensions.Add($basic)

        $now = [DateTime]::UtcNow

        $certificate = $request.CreateSelfSigned(
            $now.AddMinutes(-5),
            $now.AddDays(3650)
        )

        $pfx = $certificate.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            $Password
        )

        $der = $certificate.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Cert
        )

        Write-Binary $PfxPath $pfx
        Write-Binary $DerPath $der

        return $certificate
    }
    finally {
        $rsa.Dispose()
    }
}

# ------------------------------------------------------------
# CERTIFICATE IMPORT

function Import-DerCertificate {

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

# ------------------------------------------------------------
# EFI SIGNATURE LIST: X509

function New-EslX509 {

    param(
        [byte[]]$CertificateBytes,
        [Guid]$Owner,
        [string]$Output
    )

    $signatureSize = 16 + $CertificateBytes.Length
    $listSize = 28 + $signatureSize

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)

    try {

        $writer.Write($X509Guid.ToByteArray())
        $writer.Write([UInt32]$listSize)
        $writer.Write([UInt32]0)
        $writer.Write([UInt32]$signatureSize)

        $writer.Write($Owner.ToByteArray())
        $writer.Write($CertificateBytes)

        Write-Binary $Output $stream.ToArray()
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

# ------------------------------------------------------------
# EFI SIGNATURE LIST: SHA256

function New-EslSha256 {

    param(
        [byte[]]$Hash,
        [Guid]$Owner,
        [string]$Output
    )

    if ($Hash.Length -ne 32) {
        throw "SHA256 hash must contain 32 bytes."
    }

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)

    try {

        $writer.Write($Sha256Guid.ToByteArray())
        $writer.Write([UInt32]76)
        $writer.Write([UInt32]0)
        $writer.Write([UInt32]48)

        $writer.Write($Owner.ToByteArray())
        $writer.Write($Hash)

        Write-Binary $Output $stream.ToArray()
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}


# ============================================================
# PART 2
# KEK IMPORT, ESP DISCOVERY AND SHIM HASHING
# ============================================================

# ------------------------------------------------------------
# 1. Import current KEK certificates

function Import-CurrentKekCertificates {

    Write-Section "IMPORTING CURRENT KEK CERTIFICATES"

    if (-not (Test-Path $KekDirectory)) {
        Write-Warning "KEK-export directory not found."
        return @()
    }

    $files = @(
        Get-ChildItem -LiteralPath $KekDirectory `
            -Filter "current_kek-*.der" -File
    )

    if ($files.Count -eq 0) {
        Write-Warning "No current_kek-*.der certificates found."
        return @()
    }

    $result = @()

    foreach ($file in $files) {

        $certificate = Import-DerCertificate $file.FullName

        try {

            $der = $certificate.Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Cert
            )

            $base = [IO.Path]::GetFileNameWithoutExtension(
                $file.Name
            )

            $esl = Join-Path $OutputDirectory "$base.esl"

            New-EslX509 `
                -CertificateBytes $der `
                -Owner $ProjectGuid `
                -Output $esl

            Write-Host ""
            Write-Host "Certificate: $($file.Name)" -ForegroundColor Green
            Write-Host "Subject: $($certificate.Subject)"
            Write-Host "ESL: $esl"

            $result += $esl
        }
        finally {
            $certificate.Dispose()
        }
    }

    return $result
}

# ------------------------------------------------------------
# 2. Find shimx64.efi on EFI System Partition

function Find-ShimOnEsp {

    Write-Section "SEARCHING EFI SYSTEM PARTITION"

    if (-not $IsAdmin) {
        Write-Warning "Administrator privileges required for ESP mounting."
        return $null
    }

    $mounted = @()

    try {

        $partitions = @(
            Get-Partition |
                Where-Object {
                    $_.GptType -eq $EspGuid
                } |
                Sort-Object @{
                    Expression = {
                        if ($_.IsSystem) { 0 } else { 1 }
                    }
                }
        )

        if ($partitions.Count -eq 0) {
            Write-Warning "No EFI System Partition detected."
            return $null
        }

        foreach ($partition in $partitions) {

            $drive = $partition.DriveLetter
            $temporary = $false

            if (-not $drive) {

                $used = @(
                    Get-Volume |
                        Where-Object DriveLetter |
                        ForEach-Object {
                            [string]$_.DriveLetter
                        }
                )

                $available = @(
                    "S","T","U","V","W","X","Y","Z"
                ) | Where-Object {
                    $_ -notin $used
                }

                if (-not $available) {
                    Write-Warning "No available drive letter."
                    continue
                }

                $drive = $available[0]

                Add-PartitionAccessPath `
                    -DiskNumber $partition.DiskNumber `
                    -PartitionNumber $partition.PartitionNumber `
                    -AccessPath "${drive}:\"

                $temporary = $true
            }

            $mounted += [PSCustomObject]@{
                Drive = $drive
                Temporary = $temporary
                Partition = $partition
            }

            Write-Host "Inspecting ${drive}:\" 

            $shim = Get-ChildItem `
                -LiteralPath "${drive}:\" `
                -Filter "shimx64.efi" `
                -File -Recurse `
                -ErrorAction SilentlyContinue |
                Select-Object -First 1

            if ($shim) {

                $temporaryFile = Join-Path $env:TEMP (
                    "shimx64-" +
                    [Guid]::NewGuid().ToString("N") +
                    ".efi"
                )

                Copy-Item `
                    -LiteralPath $shim.FullName `
                    -Destination $temporaryFile

                Write-Host ""
                Write-Host "SHIM FOUND" -ForegroundColor Green
                Write-Host $shim.FullName

                return [PSCustomObject]@{
                    OriginalPath = $shim.FullName
                    TemporaryPath = $temporaryFile
                }
            }
        }

        Write-Warning "No shimx64.efi found."
        return $null
    }
    finally {

        foreach ($mount in $mounted) {

            if ($mount.Temporary) {

                Remove-PartitionAccessPath `
                    -DiskNumber $mount.Partition.DiskNumber `
                    -PartitionNumber $mount.Partition.PartitionNumber `
                    -AccessPath "$($mount.Drive):\" `
                    -ErrorAction SilentlyContinue

                Write-Host "Unmounted temporary ESP: $($mount.Drive):"
            }
        }
    }
}

# ------------------------------------------------------------
# 3. Calculate PE/COFF SHA256 image hash

function Get-PeCoffSha256 {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)

    if ($bytes.Length -lt 256 -or
        $bytes[0] -ne 0x4D -or
        $bytes[1] -ne 0x5A) {

        throw "Invalid PE image: $Path"
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)

    if ($peOffset -lt 64 -or
        $peOffset + 24 -gt $bytes.Length) {

        throw "Invalid PE header."
    }

    if ($bytes[$peOffset] -ne 0x50 -or
        $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or
        $bytes[$peOffset + 3] -ne 0) {

        throw "Invalid PE signature."
    }

    $sectionCount = [BitConverter]::ToUInt16(
        $bytes, $peOffset + 6
    )

    $optionalSize = [BitConverter]::ToUInt16(
        $bytes, $peOffset + 20
    )

    $optional = $peOffset + 24

    $magic = [BitConverter]::ToUInt16(
        $bytes, $optional
    )

    if ($magic -eq 0x10B) {

        $directory = $optional + 96
        $numberDirectoriesOffset = $optional + 92
    }
    elseif ($magic -eq 0x20B) {

        $directory = $optional + 112
        $numberDirectoriesOffset = $optional + 108
    }
    else {
        throw "Unsupported PE optional header."
    }

    $checksumOffset = $optional + 64

    $sizeOfHeaders = [BitConverter]::ToUInt32(
        $bytes, $optional + 60
    )

    $numberDirectories = [BitConverter]::ToUInt32(
        $bytes, $numberDirectoriesOffset
    )

    if ($sizeOfHeaders -gt $bytes.Length) {
        throw "Invalid PE header size."
    }

    $certificateOffset = [UInt32]0
    $certificateSize = [UInt32]0

    if ($numberDirectories -gt 4) {

        $certificateOffset = [BitConverter]::ToUInt32(
            $bytes, $directory + 32
        )

        $certificateSize = [BitConverter]::ToUInt32(
            $bytes, $directory + 36
        )
    }

    if ($certificateOffset -gt $bytes.Length -or
        $certificateSize -gt ($bytes.Length - $certificateOffset)) {

        throw "Invalid PE certificate table."
    }

    $sectionTable = $optional + $optionalSize
    $sections = @()

    for ($i = 0; $i -lt $sectionCount; $i++) {

        $position = $sectionTable + ($i * 40)

        if ($position + 40 -gt $bytes.Length) {
            throw "Invalid PE section table."
        }

        $rawSize = [BitConverter]::ToUInt32(
            $bytes, $position + 16
        )

        $rawPointer = [BitConverter]::ToUInt32(
            $bytes, $position + 20
        )

        if ($rawSize -gt 0) {

            if ($rawPointer -gt $bytes.Length -or
                $rawSize -gt ($bytes.Length - $rawPointer)) {

                throw "Invalid PE section range."
            }

            $sections += [PSCustomObject]@{
                Offset = [int]$rawPointer
                Size = [int]$rawSize
            }
        }
    }

    $stream = New-Object IO.MemoryStream

    try {

        # Hash headers excluding checksum.

        $stream.Write(
            $bytes,
            0,
            $checksumOffset
        )

        $start = $checksumOffset + 4

        # Exclude security directory entry.

        $securityDirectory = $directory + 32

        if ($numberDirectories -gt 4) {

            $stream.Write(
                $bytes,
                $start,
                $securityDirectory - $start
            )

            $start = $securityDirectory + 8
        }

        # Remaining header bytes.

        if ($sizeOfHeaders -gt $start) {

            $stream.Write(
                $bytes,
                $start,
                [int]$sizeOfHeaders - $start
            )
        }

        $sumHashed = [long]$sizeOfHeaders

        # Hash sections in file-offset order.

        foreach ($section in ($sections | Sort-Object Offset)) {

            $stream.Write(
                $bytes,
                $section.Offset,
                $section.Size
            )

            $sumHashed += $section.Size
        }

        # Hash remaining data, excluding certificate table.

        $extraEnd = if ($certificateSize -gt 0) {
            [long]$certificateOffset
        }
        else {
            [long]$bytes.Length
        }

        if ($extraEnd -lt $sumHashed) {
            throw "Invalid PE image layout."
        }

        $extraLength = $extraEnd - $sumHashed

        if ($extraLength -gt 0) {

            if ($sumHashed + $extraLength -gt $bytes.Length) {
                throw "Invalid PE overlay."
            }

            $stream.Write(
                $bytes,
                [int]$sumHashed,
                [int]$extraLength
            )
        }

        $sha = [Security.Cryptography.SHA256]::Create()

        try {
            return $sha.ComputeHash($stream.ToArray())
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

# ------------------------------------------------------------
# 4. Generate shim hash ESL

function Add-ShimHashToDb {

    Write-Section "GENERATING SHIM HASH"

    $shim = Find-ShimOnEsp

    if (-not $shim) {
        Write-Warning "Shim hash skipped."
        return $false
    }

    try {

        $hash = Get-PeCoffSha256 $shim.TemporaryPath

        $fingerprint = (
            [BitConverter]::ToString($hash)
        ).Replace("-", "")

        Write-Host ""
        Write-Host "Shim location:"
        Write-Host $shim.OriginalPath

        Write-Host ""
        Write-Host "PE/COFF SHA256:"
        Write-Host $fingerprint -ForegroundColor Green

        $output = Join-Path $OutputDirectory "shim_hash.esl"

        New-EslSha256 `
            -Hash $hash `
            -Owner $ProjectGuid `
            -Output $output

        Write-Host ""
        Write-Host "Generated: $output" -ForegroundColor Green

        return $true
    }
    finally {

        Remove-Item $shim.TemporaryPath `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

# ============================================================
# PART 3
# KEY GENERATION, DB/DBX AND FINAL REPORT
# ============================================================


# ------------------------------------------------------------
# EFI SIGNATURE LIST: DBX SHA256 HASHES
#
# Input format:
# One SHA256 hexadecimal hash per line.
# Optional whitespace and comments beginning with #.
#
# Output:
# EFI_SIGNATURE_LIST containing EFI_CERT_SHA256 entries.

function New-DbxEsl {

    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile,

        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
        throw "DBX input file not found: $InputFile"
    }

    $lines = Get-Content -LiteralPath $InputFile

    $hashes = @()

    foreach ($line in $lines) {

        $line = $line.Trim()

        # Skip empty lines and comments.
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line.StartsWith("#")) {
            continue
        }

        # Remove optional SHA256 prefix.
        $line = $line -replace "^(Hash:|SHA256:|SHA256=)", ""

        $line = $line.Trim()

        # Validate hexadecimal SHA256.
        if ($line -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Invalid SHA256 hash in dbx.txt: $line"
        }

        [byte[]]$hash = New-Object byte[] 32

        for ($i = 0; $i -lt 32; $i++) {

            $hash[$i] = [Convert]::ToByte(
                $line.Substring($i * 2, 2),
                16
            )
        }

        $hashes += ,$hash
    }

    if ($hashes.Count -eq 0) {
        throw "No valid SHA256 hashes found in dbx.txt."
    }

    # Each EFI_SIGNATURE_DATA:
    # 16 bytes SignatureOwner + 32 bytes SHA256.
    $signatureSize = 48

    # EFI_SIGNATURE_LIST header = 28 bytes.
    $listSize = 28 + ($hashes.Count * $signatureSize)

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)

    try {

        # EFI_CERT_SHA256 GUID.
        $writer.Write($Sha256Guid.ToByteArray())

        $writer.Write([UInt32]$listSize)
        $writer.Write([UInt32]0)
        $writer.Write([UInt32]$signatureSize)

        foreach ($hash in $hashes) {

            # SignatureOwner.
            $writer.Write($ProjectGuid.ToByteArray())

            # SHA256 digest.
            $writer.Write($hash)
        }

        Write-Binary -Path $Output -Bytes $stream.ToArray()

    }
    finally {

        $writer.Dispose()
        $stream.Dispose()
    }

    Write-Host ""
    Write-Host "DBX SHA256 hashes processed: $($hashes.Count)" `
        -ForegroundColor Green

    Write-Host "DBX ESL: $Output"
}

# ------------------------------------------------------------
# 1. Generate PK

Write-Section "GENERATING PLATFORM KEY"

$passwordSecure = Read-Host `
    "Enter a password to protect private keys" `
    -AsSecureString

$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
    $passwordSecure
)

try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}

$pk = $null
$kek = $null
$db = $null

try {

    $pk = New-SecureBootCertificate `
        -CommonName "Shokubai Infrastructure Authority" `
        -PfxPath "$KeyDirectory\PK.pfx" `
        -DerPath "$OutputDirectory\PK.cer" `
        -Password $password

    $pkDer = $pk.Export(
        [Security.Cryptography.X509Certificates.X509ContentType]::Cert
    )

    New-EslX509 `
        -CertificateBytes $pkDer `
        -Owner $ProjectGuid `
        -Output "$OutputDirectory\PK.esl"

    Write-Host "PK certificate generated." -ForegroundColor Green

    # --------------------------------------------------------
    # 2. Generate KEK

    Write-Section "GENERATING KEY EXCHANGE KEY"

    $kek = New-SecureBootCertificate `
        -CommonName "Shokubai Security Authority" `
        -PfxPath "$KeyDirectory\KEK.pfx" `
        -DerPath "$OutputDirectory\KEK.cer" `
        -Password $password

    $kekDer = $kek.Export(
        [Security.Cryptography.X509Certificates.X509ContentType]::Cert
    )

    New-EslX509 `
        -CertificateBytes $kekDer `
        -Owner $ProjectGuid `
        -Output "$OutputDirectory\KEK.esl"

    Write-Host "KEK certificate generated." -ForegroundColor Green

    # --------------------------------------------------------
    # 3. Generate DB

    Write-Section "GENERATING SIGNATURE DATABASE"

    $db = New-SecureBootCertificate `
        -CommonName "Shokubai Engineering Authority" `
        -PfxPath "$KeyDirectory\db.pfx" `
        -DerPath "$OutputDirectory\db.cer" `
        -Password $password

    $dbDer = $db.Export(
        [Security.Cryptography.X509Certificates.X509ContentType]::Cert
    )

    New-EslX509 `
        -CertificateBytes $dbDer `
        -Owner $ProjectGuid `
        -Output "$OutputDirectory\db_base.esl"

    # --------------------------------------------------------
    # 4. Import current KEK certificates

    Write-Section "IMPORTING EXISTING KEK CERTIFICATES"

    $dbLists = @(
        "$OutputDirectory\db_base.esl"
    )

    $currentKekLists = @(
        Import-CurrentKekCertificates
    )

    foreach ($file in $currentKekLists) {
        $dbLists += $file
    }

    # --------------------------------------------------------
    # 5. Import optional SUSE certificate

    Write-Section "IMPORTING SUSE CERTIFICATE"

    if (Test-Path $SuseCertificate) {

        $suse = Import-DerCertificate $SuseCertificate

        try {

            $suseDer = $suse.Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Cert
            )

            $suseEsl = "$OutputDirectory\soliddriver.esl"

            New-EslX509 `
                -CertificateBytes $suseDer `
                -Owner $ProjectGuid `
                -Output $suseEsl

            $dbLists += $suseEsl

            Write-Host "Imported: $($suse.Subject)" `
                -ForegroundColor Green
        }
        finally {
            $suse.Dispose()
        }
    }
    else {
        Write-Host "SUSE certificate not found. Skipping."
    }

    # --------------------------------------------------------
    # 6. Generate shim hash

    Write-Section "ADDING SHIM HASH"

    $shimAdded = Add-ShimHashToDb

    if ($shimAdded) {
        $dbLists += "$OutputDirectory\shim_hash.esl"
    }

    # --------------------------------------------------------
    # 7. Combine DB ESL files

    Write-Section "COMBINING DB SIGNATURE LISTS"

    Join-BinaryFiles `
        -Files $dbLists `
        -Output "$OutputDirectory\db.esl"

    Write-Host "db.esl generated." -ForegroundColor Green

    # --------------------------------------------------------
    # 8. Generate DBX ESL

    Write-Section "GENERATING DBX"

    if (Test-Path $DbxFile) {

        New-DbxEsl `
            -InputFile $DbxFile `
            -Output "$OutputDirectory\dbx.esl"

        Write-Host "dbx.esl generated."
    }
    else {
        Write-Host "dbx.txt not found. Skipping DBX."
    }

    # --------------------------------------------------------
    # 9. Final report

    Write-Section "BUILD SUMMARY"

    Write-Host "Project GUID: $ProjectGuid"
    Write-Host "KEK certificates imported: $($currentKekLists.Count)"
    Write-Host "Shim included: $shimAdded"

    Write-Host ""
    Write-Host "Generated files:" -ForegroundColor Cyan

    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Sort-Object Name |
        Select-Object Name, Length |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Private keys:" -ForegroundColor Cyan

    Get-ChildItem -LiteralPath $KeyDirectory -File |
        Select-Object Name, Length |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Output directory:"
    Write-Host $OutputDirectory

    Write-Host ""
    Write-Host "BUILD COMPLETED." -ForegroundColor Green

    Write-Host ""
    Write-Host "IMPORTANT:"
    Write-Host " - No firmware variables were modified."
    Write-Host " - PK.auth has NOT been generated."
    Write-Host " - ESL files require independent validation."
    Write-Host " - Do not enroll until signature and hash formats are verified."

}
finally {

    if ($pk) { $pk.Dispose() }
    if ($kek) { $kek.Dispose() }
    if ($db) { $db.Dispose() }

    $password = $null
    $passwordSecure.Dispose()
}

