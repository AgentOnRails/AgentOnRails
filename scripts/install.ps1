# AgentOnRails installer for Windows.
# Usage (PowerShell):
#   iwr https://raw.githubusercontent.com/agentOnRails/agent-on-rails/main/scripts/install.ps1 -useb | iex
#
# Mirrors scripts/install.sh's logic (resolve latest release tag from the
# GitHub API, download the matching GoReleaser archive, install, verify) —
# install.sh explicitly refuses non-Linux/Darwin, so this is the Windows
# counterpart rather than an extension of it.

$ErrorActionPreference = "Stop"

$Repo = "agentOnRails/agent-on-rails"
$Binary = "aor"
$InstallDir = if ($env:AOR_INSTALL_DIR) { $env:AOR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "aor\bin" }

# ── detect arch ──────────────────────────────────────────────────────────────

switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { $Arch = "amd64" }
  "ARM64" { $Arch = "arm64" }
  default {
    Write-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
    exit 1
  }
}

# ── resolve version ──────────────────────────────────────────────────────────

$Version = $env:AOR_VERSION
if (-not $Version) {
  $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
  $Version = $release.tag_name
}
if (-not $Version) {
  Write-Error "Could not determine latest version. Set `$env:AOR_VERSION = 'vX.Y.Z' to install a specific version."
  exit 1
}

Write-Host "Installing $Binary $Version (windows/$Arch) -> $InstallDir\$Binary.exe"

# ── download ─────────────────────────────────────────────────────────────────

# GoReleaser names archive assets without the tag's leading "v" (e.g. tag
# v0.1.0 -> aor_0.1.0_windows_amd64.zip) even though the release path
# itself uses the full tag — strip it here, not from $Version, so the
# download path below still resolves.
$ArchiveVersion = $Version -replace '^v', ''
$Filename = "${Binary}_${ArchiveVersion}_windows_${Arch}.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Filename"

$Tmp = Join-Path $env:TEMP ("aor-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
try {
  $ArchivePath = Join-Path $Tmp $Filename
  Invoke-WebRequest -Uri $Url -OutFile $ArchivePath -UseBasicParsing
  Expand-Archive -Path $ArchivePath -DestinationPath $Tmp -Force

  # ── install ──────────────────────────────────────────────────────────────

  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Copy-Item -Path (Join-Path $Tmp "$Binary.exe") -Destination (Join-Path $InstallDir "$Binary.exe") -Force

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($userPath -split ";") -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "Added $InstallDir to your user PATH (open a new terminal for it to take effect elsewhere)."
  }
}
finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

# ── verify ───────────────────────────────────────────────────────────────────

Write-Host ""
& (Join-Path $InstallDir "$Binary.exe") version
Write-Host ""
Write-Host "Run 'aor init' to create your config directory."
