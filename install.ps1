# VouchProxy Windows PowerShell Installer
$ErrorActionPreference = 'Stop'

$Repo = "sshloktiwarii/vouchproxy"
$Version = if ($env:VOUCH_VERSION) { $env:VOUCH_VERSION.TrimStart('v') } else { "1.1.0" }

$Arch = "amd64"
if ([System.Environment]::Is64BitOperatingSystem -eq $false) {
    Write-Error "Unsupported architecture. VouchProxy requires 64-bit Windows."
    exit 1
}

$Archive = "vouchproxy_${Version}_windows_${Arch}.zip"
$Checksums = "checksums.txt"
$BaseUrl = "https://github.com/$Repo/releases/download/v$Version"

Write-Host "Installing VouchProxy v$Version (windows/$Arch)..." -ForegroundColor Cyan

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ArchiveUrl = "$BaseUrl/$Archive"
    $ChecksumUrl = "$BaseUrl/$Checksums"
    $ArchivePath = Join-Path $TempDir $Archive
    $ChecksumPath = Join-Path $TempDir $Checksums

    $Headers = @{}
    if ($env:GITHUB_TOKEN) {
        $Headers["Authorization"] = "token $env:GITHUB_TOKEN"
    } elseif ($env:GH_TOKEN) {
        $Headers["Authorization"] = "token $env:GH_TOKEN"
    }

    Write-Host "Downloading $Archive..."
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $ArchivePath -Headers $Headers -UseBasicParsing
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -Headers $Headers -UseBasicParsing

    Write-Host "Verifying SHA-256 checksum..."
    $ExpectedHash = (Get-Content $ChecksumPath | Select-String $Archive).ToString().Split(' ')[0].Trim()
    $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLower()

    if ($ExpectedHash -ne "" -and $ActualHash -ne $ExpectedHash.ToLower()) {
        Write-Error "Checksum verification failed! Expected: $ExpectedHash, Got: $ActualHash"
        exit 1
    }

    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\vouchproxy"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    Expand-Archive -Path $ArchivePath -DestinationPath $TempDir -Force
    Copy-Item -Path (Join-Path $TempDir "vouchproxy.exe") -Destination (Join-Path $InstallDir "vouchproxy.exe") -Force

    # Ensure in User PATH
    $UserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if (-not ($UserPath -split ';' -contains $InstallDir)) {
        [System.Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "Added $InstallDir to user PATH." -ForegroundColor Green
    }

    Write-Host "`n✓ VouchProxy v$Version successfully installed to $InstallDir\vouchproxy.exe" -ForegroundColor Green
    Write-Host "`nGet started in PowerShell:"
    Write-Host "  vouchproxy init"
    Write-Host "  vouchproxy env | Invoke-Expression"
} finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
