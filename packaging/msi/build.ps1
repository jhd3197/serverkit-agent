# Build MSI installer for ServerKit Agent
# Usage: .\build.ps1 -Version "1.0.0" -BinaryPath "..\dist\serverkit-agent-windows-amd64.exe"

param(
    [string]$Version = "1.0.0",
    [string]$BinaryPath = "..\..\dist\serverkit-agent-windows-amd64.exe",
    [string]$OutputDir = ".\output",
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

Write-Host "Building MSI installer..."
Write-Host "  Version: $Version"
Write-Host "  Arch:    $Arch"
Write-Host "  Binary:  $BinaryPath"

# Check for WiX Toolset
$wixPath = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wixPath) {
    Write-Host "WiX Toolset not found. Please install it first:"
    Write-Host "  dotnet tool install --global wix --version 5.0.2"
    Write-Host "  or download from: https://wixtoolset.org/"
    exit 1
}

# The Product.wxs file requires the WiX Util extension. Verify it is installed
# so the failure message is actionable instead of the raw WiX WIX0144 error.
$extensionList = wix extension list --global 2>&1
if (-not ($extensionList -match "WixToolset\.Util\.wixext")) {
    Write-Host "WiX Util extension not found. Install it with:"
    Write-Host "  wix extension add --global WixToolset.Util.wixext/5.0.2"
    exit 1
}

# Create build directory
$buildDir = New-Item -ItemType Directory -Force -Path "$env:TEMP\serverkit-msi-build-$(Get-Random)"
Write-Host "Build directory: $buildDir"

try {
    # Copy binary
    Copy-Item $BinaryPath "$buildDir\serverkit-agent.exe"

    # Copy brand icon (used by the installer banner / Add-Remove Programs entry)
    $iconSource = Join-Path $PSScriptRoot "..\..\internal\setupui\serverkit.ico"
    if (-not (Test-Path $iconSource)) {
        Write-Host "Brand icon not found at $iconSource - run agent/packaging/icons/generate_icons.py first."
        exit 1
    }
    Copy-Item $iconSource "$buildDir\serverkit.ico"

    # Copy SmartScreen-bypass launcher script (see launcher.vbs for rationale).
    Copy-Item (Join-Path $PSScriptRoot "launcher.vbs") "$buildDir\launcher.vbs"

    # Create default config file
    $configContent = @"
# ServerKit Agent Configuration
# This file is created during installation.
# Run 'serverkit-agent register' to configure the agent.

server:
  url: ""
  reconnect_interval: 5s
  max_reconnect_interval: 5m
  ping_interval: 30s

agent:
  id: ""
  name: ""

features:
  docker: true
  metrics: true
  logs: true
  file_access: false
  exec: false

metrics:
  enabled: true
  interval: 10s

docker:
  socket: npipe:////./pipe/docker_engine
  timeout: 30s

logging:
  level: info
  file: C:\ProgramData\ServerKit\Agent\logs\agent.log
  max_size_mb: 100
  max_backups: 5
  max_age_days: 30
  compress: true

ipc:
  enabled: true
  port: 19780
  address: 127.0.0.1
"@
    $configContent | Out-File -FilePath "$buildDir\config.yaml" -Encoding UTF8

    # Create license file (RTF format required by WiX)
    $licenseContent = @"
{\rtf1\ansi\deff0
{\fonttbl{\f0 Consolas;}}
\f0\fs20
MIT License\par
\par
Copyright (c) 2024 ServerKit\par
\par
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:\par
\par
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.\par
\par
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\par
}
"@
    $licenseContent | Out-File -FilePath "$buildDir\License.rtf" -Encoding ASCII

    # Copy WiX source
    Copy-Item "Product.wxs" "$buildDir\"

    # Create output directory (resolve to absolute path so it survives Push-Location)
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $absOutputDir = (Resolve-Path $OutputDir).Path

    # Build MSI
    Push-Location $buildDir
    try {
        Write-Host "Running WiX build..."
        wix build -arch $Arch Product.wxs -ext WixToolset.Util.wixext -o "$absOutputDir\serverkit-agent-$Version-$Arch.msi" -define Version=$Version
        if ($LASTEXITCODE -ne 0) {
            throw "WiX build failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }

    $msiPath = "$absOutputDir\serverkit-agent-$Version-$Arch.msi"
    if (-not (Test-Path $msiPath)) {
        throw "MSI output not found at $msiPath"
    }

    Write-Host ""
    Write-Host "MSI built successfully!"
    Write-Host "Output: $msiPath"
}
finally {
    # Cleanup
    Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue
}
