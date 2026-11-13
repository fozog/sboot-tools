# Export-CurrentKEK.ps1
# Extract X.509 certificates from the current UEFI KEK database.
# Compatible with Windows PowerShell 5.1

$ErrorActionPreference = "Stop"

# Check administrator privileges
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run PowerShell as Administrator."
}

# Create output directory
$OutputDir = Join-Path (Get-Location) "KEK-Export"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host "Reading UEFI KEK variable..."

$variable = Get-SecureBootUEFI -Name KEK
[byte[]]$data = $variable.Bytes

if ($data.Length -eq 0) {
    throw "The KEK variable is empty."
}

# EFI Signature List GUID for X.509 certificates
$X509Guid = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"

$offset = 0
$index = 0

while ($offset -lt $data.Length) {

    # Ensure enough bytes for EFI_SIGNATURE_LIST header
    if (($data.Length - $offset) -lt 28) {
        throw "Invalid ESL header at offset $offset"
    }

    # Read EFI_SIGNATURE_LIST header
    $typeGuid = New-Object Guid (
        [byte[]]$data[$offset..($offset + 15)]
    )

    $listSize = [BitConverter]::ToUInt32(
        $data, $offset + 16
    )

    $headerSize = [BitConverter]::ToUInt32(
        $data, $offset + 20
    )

    $signatureSize = [BitConverter]::ToUInt32(
        $data, $offset + 24
    )

    if ($listSize -lt (28 + $headerSize) -or
        $listSize -gt ($data.Length - $offset)) {
        throw "Invalid EFI signature list size."
    }

    if ($signatureSize -lt 16) {
        throw "Invalid signature size."
    }

    $entriesOffset = $offset + 28 + $headerSize
    $entriesSize = $listSize - 28 - $headerSize

    if (($entriesSize % $signatureSize) -ne 0) {
        throw "Invalid signature entry alignment."
    }

    # Process X.509 certificate lists only
    if ($typeGuid -eq $X509Guid) {

        $entryCount = $entriesSize / $signatureSize

        for ($i = 0; $i -lt $entryCount; $i++) {

            $entryOffset = $entriesOffset +
                ($i * $signatureSize)

            # Skip 16-byte SignatureOwner GUID
            $certOffset = $entryOffset + 16
            $certLength = $signatureSize - 16

            [byte[]]$certBytes = $data[
                $certOffset..($certOffset + $certLength - 1)
            ]

            try {
                $cert = New-Object `
                    System.Security.Cryptography.X509Certificates.X509Certificate2 `
                    -ArgumentList (,$certBytes)

                $fileName = "current_kek-$index.der"
                $filePath = Join-Path $OutputDir $fileName

                [IO.File]::WriteAllBytes(
                    $filePath,
                    $cert.Export(
                        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
                    )
                )

                $sha = [Security.Cryptography.SHA256]::Create()
                $fingerprint = [BitConverter]::ToString(
                    $sha.ComputeHash($certBytes)
                ).Replace("-", "")

                Write-Host ""
                Write-Host "Exported: $fileName"
                Write-Host "Subject: $($cert.Subject)"
                Write-Host "SHA256: $fingerprint"

                $index++
            }
            catch {
                Write-Warning "Could not parse certificate: $_"
            }
        }
    }

    $offset += $listSize
}

Write-Host ""
Write-Host "--------------------------------"
Write-Host "Export completed."
Write-Host "Certificates exported: $index"
Write-Host "Output directory: $OutputDir"
Write-Host "--------------------------------"

if ($index -eq 0) {
    Write-Warning "No X.509 certificates were found in KEK."
}