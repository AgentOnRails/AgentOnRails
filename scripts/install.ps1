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

# ── optional: aor-pro (commercial add-ons — identity, privacy, Dispatch) ─────
#
# aor-pro has no public binary release yet (unlike aor above, which
# GoReleaser publishes to this repo's own GitHub releases) — the private
# repo isn't public, so there's nothing to download by URL. The only way to
# get an aor-pro binary today is building it from that repo's source, which
# this step does IF $env:AOR_PRO_SRC_DIR points at a local checkout AND you
# have a Pro license token to activate. Deliberately not guessed from the
# current directory: this script's documented usage is a one-liner run from
# anywhere, so "look for a sibling directory" would be right only by
# coincidence. Neither set: nothing below runs, and everything above this
# line behaves exactly as it always has.
$existingLicense = Join-Path $env:USERPROFILE ".aor-pro\license.key"
if ($env:AOR_PRO_LICENSE_TOKEN -or (Test-Path $existingLicense)) {
  $goCmd = Get-Command go -ErrorAction SilentlyContinue
  if ($env:AOR_PRO_SRC_DIR -and (Test-Path $env:AOR_PRO_SRC_DIR) -and $goCmd) {
    Write-Host ""
    Write-Host "Pro license detected — building aor-pro from $env:AOR_PRO_SRC_DIR ..."
    Push-Location $env:AOR_PRO_SRC_DIR
    try {
      & go build -o (Join-Path $InstallDir "aor-pro.exe") ./cmd/aor-pro/
    } finally {
      Pop-Location
    }

    # Both calls below are best-effort: activation can fail on a bad/expired
    # token and "show" has nothing to report on a fresh vault-dir. A native
    # exe's non-zero exit doesn't raise a catchable PowerShell error, but it
    # does set $LASTEXITCODE — reset that explicitly afterward so a caller
    # scripting against this installer's own exit code doesn't see a false
    # failure from an intentionally-tolerated one here.
    if ($env:AOR_PRO_LICENSE_TOKEN -and -not (Test-Path $existingLicense)) {
      & (Join-Path $InstallDir "aor-pro.exe") license activate $env:AOR_PRO_LICENSE_TOKEN
      $LASTEXITCODE = 0
    }

    Write-Host ""
    & (Join-Path $InstallDir "aor-pro.exe") license show
    $LASTEXITCODE = 0
    Write-Host ""
    Write-Host "aor-pro installed. Run 'aor-pro onboard --agent <id>' for the guided path to a"
    Write-Host "fully protected agent (wallet, Cargo privacy rail, Track identity), or"
    Write-Host "'aor-pro doctor' to check an existing setup."
  } else {
    Write-Host ""
    Write-Host "A Pro license was detected, but aor-pro has no public binary download yet."
    Write-Host "If you have access to the private repo, set `$env:AOR_PRO_SRC_DIR to your"
    Write-Host "local checkout's path and re-run this installer."
  }
}
