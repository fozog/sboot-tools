Installing Microsoft SignTool (without the full Windows SDK)

SignTool is required to sign Secure Boot authenticated variable updates using the private key stored in the PK PFX file.

Instead of installing the complete Windows SDK, we use Microsoft's Windows SDK Build Tools NuGet package.

1. Download NuGet

Download the standalone NuGet command-line client:

powershell
Invoke-WebRequest `
    -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" `
    -OutFile ".\nuget.exe"

2. Install Windows SDK Build Tools

Download and extract the package locally:

powershell
.\nuget.exe install Microsoft.Windows.SDK.BuildTools -x


This installs the Build Tools package without requiring the full Windows SDK installation.

3. Locate SignTool

Find the available executables:

powershell
Get-ChildItem . -Filter signtool.exe -Recurse |
    Select-Object -ExpandProperty FullName


The package normally contains executables for multiple architectures:

x64
arm64
x86
4. Automatically select the correct architecture

The following PowerShell code detects the Windows operating-system architecture and selects the corresponding executable.

powershell
$osArchitecture = (
    Get-CimInstance Win32_OperatingSystem
).OSArchitecture

switch -Regex ($osArchitecture) {
    "ARM64" {
        $signToolArchitecture = "arm64"
        break
    }
    "64-bit" {
        $signToolArchitecture = "x64"
        break
    }
    "32-bit" {
        $signToolArchitecture = "x86"
        break
    }
    default {
        throw "Unsupported OS architecture: $osArchitecture"
    }
}

$sdkDirectory = Join-Path $Root "Microsoft.Windows.SDK.BuildTools"

if (-not (Test-Path -LiteralPath $sdkDirectory)) {
    throw "Windows SDK Build Tools directory not found."
}

$signTool = Get-ChildItem `
    -LiteralPath $sdkDirectory `
    -Filter "signtool.exe" `
    -File `
    -Recurse |
    Where-Object {
        $_.Directory.Name -eq $signToolArchitecture
    } |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $signTool) {
    throw "SignTool for $signToolArchitecture was not found."
}

Write-Host "Operating system: $osArchitecture"
Write-Host "Selected architecture: $signToolArchitecture"
Write-Host "SignTool: $signTool" -ForegroundColor Green

5. Verify SignTool

Check that the executable starts correctly:

powershell
& $signTool /?

if ($LASTEXITCODE -ne 0) {
    throw "SignTool failed its startup check."
}


Display the signing-specific options:

powershell
& $signTool sign /?

6. Sign Secure Boot update data

The signing operation uses the existing PK PFX certificate and private key.

powershell
& $signTool sign `
    /fd SHA256 `
    /p7 $OutputDirectory `
    /p7co 1.2.840.113549.1.7.1 `
    /p7ce DetachedSignedData `
    /a `
    /f $pkPfxPath `
    /p $password `
    $pkSignablePath

if ($LASTEXITCODE -ne 0) {
    throw "SignTool failed with exit code $LASTEXITCODE."
}


The password is obtained earlier in the customization script using Read-Host -AsSecureString and converted to $password for the signing operation.

Security note: SignTool's /p argument exposes the PFX password in the process command line while signing. Avoid running this operation in an environment where other users or processes can inspect command-line arguments.

References
Microsoft Windows SDK
Microsoft.Windows.SDK.BuildTools – NuGet
Microsoft SignTool documentation
Microsoft SecureBoot PowerShell module

Note: SignTool is used here to produce the detached PKCS#7 signature required by the Windows Secure Boot signing workflow. The resulting signature must be submitted together with the corresponding formatted variable data using Set-SecureBootUEFI.