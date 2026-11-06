<#
.SYNOPSIS
    Provisions a WSL2 (Ubuntu) environment with an open-source URL-enumeration /
    External Attack Surface Management (EASM) toolchain.

.DESCRIPTION
    1. Checks prerequisites (Windows build, admin rights, virtualization/WSL).
    2. Installs/updates WSL2 and an Ubuntu distribution if needed.
    3. Provisions the distro (run as root, system-wide under /opt/recon):
         - apt base packages (git, python3-venv, build-essential, jq, libpcap, ...)
         - Go toolchain (pinned) -> /usr/local/go
         - Go tools -> /usr/local/bin: gau, waybackurls, httpx, katana, subfinder,
           dnsx, tlsx, alterx, nuclei, hakrawler, gospider, ffuf, subjs, getJS,
           urlfinder, anew, unfurl, qsreplace, gf, plus v1.4.0: naabu, shuffledns,
           puredns, massdns, asnmap, mapcidr, cdncheck, uncover, notify, amass,
           assetfinder, findomain, subzy, gowitness, jsluice, trufflehog,
           github-subdomains, github-endpoints, cloud_enum, dnsvalidator,
           wpscan, droopescan, joomscan, cmseek, whatweb
         - pipx (isolated venvs) -> /usr/local/bin: waymore, arjun, uro, dirsearch,
           xnLinkFinder
         - git + dedicated venvs: LinkFinder, SecretFinder
         - (optional, -IncludeHeavyTools) SecLists wordlists, nuclei-templates,
           feroxbuster
    4. Installs the companion run-recon.sh (found next to this script) into the
       distro at /opt/recon/bin/run-recon.sh and symlinks it to /usr/local/bin/run-recon.

.PARAMETER Distro
    WSL distribution name to use/install. Default: Ubuntu.

.PARAMETER InstallRoot
    Linux path where the toolkit is installed. Default: /opt/recon.

.PARAMETER IncludeHeavyTools
    Also install SecLists (~1GB+), nuclei-templates, and feroxbuster.

.PARAMETER SkipWslInstall
    Assume WSL2 + the distro already exist; only run provisioning.

.PARAMETER Force
    Reinstall/upgrade tools even if already present.

.EXAMPLE
    # First run (installs WSL if needed; may require a reboot + re-run):
    powershell -ExecutionPolicy Bypass -File .\Setup-ReconEnv.ps1

.EXAMPLE
    # Full install including wordlists and templates:
    .\Setup-ReconEnv.ps1 -IncludeHeavyTools

.NOTES
    Run from an ELEVATED PowerShell the first time (WSL feature install needs admin).
    Authorization: only enumerate assets your organization owns or may assess.
#>
[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu',
    [string]$InstallRoot = '/opt/recon',
    [switch]$IncludeHeavyTools,
    [switch]$SkipWslInstall,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
function Write-Step { param([string]$m) Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[+] $m"  -ForegroundColor Green }
function Write-Warn2{ param([string]$m) Write-Host "[!] $m"  -ForegroundColor Yellow }
function Write-ErrX { param([string]$m) Write-Host "[x] $m"  -ForegroundColor Red }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function ConvertTo-WslPath {
    param([Parameter(Mandatory)][string]$WinPath)
    $full  = [System.IO.Path]::GetFullPath($WinPath)
    $drive = $full.Substring(0,1).ToLower()
    $rest  = $full.Substring(2) -replace '\\','/'
    return "/mnt/$drive$rest"
}

function Get-WslDistros {
    # Returns array of installed distro names (handles UTF-16 output).
    $prev = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $out = & wsl.exe -l -q 2>$null
    } catch { $out = @() } finally { [Console]::OutputEncoding = $prev }
    if (-not $out) { return @() }
    return @($out | ForEach-Object { ($_ -replace "`0","").Trim() } | Where-Object { $_ -ne '' })
}

function Test-WslPresent {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }
    try { & wsl.exe --status *> $null; return ($LASTEXITCODE -eq 0) } catch { return $false }
}

function Test-DistroReady {
    param([string]$d)
    try { & wsl.exe -d $d -u root -- true *> $null; return ($LASTEXITCODE -eq 0) }
    catch { return $false }
}

function Write-LfFile {
    # Write text with LF line endings, UTF-8 without BOM (so bash is happy).
    param([string]$Path, [string]$Text)
    $lf = $Text -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($Path, $lf, (New-Object System.Text.UTF8Encoding($false)))
}

# ===========================================================================
# The Linux-side provisioning script (single-quoted here-string: PowerShell does
# NOT expand $ here; values are injected via environment on the wsl invocation).
# ===========================================================================
$ProvisionScript = @'
#!/usr/bin/env bash
# Provision the recon toolkit. NOTE: no `set -e` so one failed tool does not
# abort the whole run; each install is individually guarded.
set -uo pipefail

RECON_ROOT="${RECON_ROOT:-/opt/recon}"
INCLUDE_HEAVY="${INCLUDE_HEAVY:-0}"
FORCE="${FORCE:-0}"
GO_VERSION="1.24.5"
export DEBIAN_FRONTEND=noninteractive
export GOTOOLCHAIN=auto

log(){ printf '\n\033[1;34m[*]\033[0m %s\n' "$*"; }
ok(){ printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
  warn "Not running as root; some steps may fail. Re-run via: wsl -u root"
fi

mkdir -p "$RECON_ROOT/go" "$RECON_ROOT/pipx" "$RECON_ROOT/tools" \
         "$RECON_ROOT/wordlists" "$RECON_ROOT/bin"

# --- 1) base packages ------------------------------------------------------
log "apt-get update + base packages (this can take a few minutes)..."
apt-get update -y || warn "apt-get update reported errors"
apt-get install -y --no-install-recommends \
  git curl wget unzip zip ca-certificates build-essential pkg-config \
  python3 python3-venv python3-pip pipx \
  jq dnsutils whois libpcap-dev gcc make \
  ruby ruby-dev whatweb \
  || warn "some apt packages failed to install"
update-ca-certificates 2>/dev/null || true

# --- 2) Go toolchain (pinned) ---------------------------------------------
install_go(){
  if [ -x /usr/local/go/bin/go ] && [ "$FORCE" != "1" ]; then
    ok "Go present: $(/usr/local/go/bin/go version 2>/dev/null)"; return 0
  fi
  local arch goarch tgz url
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)  goarch=amd64 ;;
    aarch64|arm64) goarch=arm64 ;;
    *)             goarch=amd64 ;;
  esac
  tgz="/tmp/go${GO_VERSION}.linux-${goarch}.tar.gz"
  url="https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz"
  log "Downloading Go ${GO_VERSION} (${goarch})..."
  if curl -fsSL "$url" -o "$tgz"; then
    rm -rf /usr/local/go
    if tar -C /usr/local -xzf "$tgz"; then ok "Go installed to /usr/local/go"; else warn "Go extract failed"; fi
  else
    warn "Go download failed ($url). Go-based tools will be skipped."
  fi
}
install_go
export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
export GOPATH="$RECON_ROOT/go"
export GOMODCACHE="$RECON_ROOT/go/pkg/mod"

# --- 3) Go tools -> /usr/local/bin ----------------------------------------
goinstall(){ # <module> <binname>
  local mod="$1" name="$2"
  if have "$name" && [ "$FORCE" != "1" ]; then ok "$name present"; return 0; fi
  if [ ! -x /usr/local/go/bin/go ]; then warn "go missing; skip $name"; return 1; fi
  log "go install $name"
  if GOBIN=/usr/local/bin /usr/local/go/bin/go install "$mod" >"/tmp/go_${name}.log" 2>&1; then
    ok "installed $name"
  else
    warn "FAILED $name (tail: $(tail -n1 /tmp/go_${name}.log 2>/dev/null))"
  fi
}
log "Installing Go-based tooling..."
# Versions are pinned to match setup-recon-env.sh (output formats change between releases;
# the ProjectDiscovery tools were checked in the benchmark lab at these versions).
# Upgrade deliberately: change a pin, re-run bench-run-recon.sh, then update both scripts.
goinstall github.com/lc/gau/v2/cmd/gau@v2.2.4                          gau
goinstall github.com/tomnomnom/waybackurls@v0.1.0                      waybackurls
goinstall github.com/tomnomnom/anew@v0.1.1                             anew
goinstall github.com/tomnomnom/unfurl@v0.4.3                           unfurl
goinstall github.com/tomnomnom/qsreplace@v0.0.3                        qsreplace
goinstall github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5                               gf
goinstall github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0           httpx
# expose PD httpx as 'httpx-toolkit' (run-recon's default name; dodges python3-httpx)
if have httpx && [ ! -e /usr/local/bin/httpx-toolkit ]; then ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit; fi
goinstall github.com/projectdiscovery/katana/cmd/katana@v1.8.0         katana
goinstall github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0 subfinder
goinstall github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1             dnsx
goinstall github.com/projectdiscovery/tlsx/cmd/tlsx@v1.4.0             tlsx
goinstall github.com/projectdiscovery/alterx/cmd/alterx@v0.1.0         alterx
goinstall github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1      nuclei
goinstall github.com/hakluke/hakrawler@v0.0.0-20260805040537-52a16fe61bd1                          hakrawler
goinstall github.com/jaeles-project/gospider@v1.1.6                    gospider
goinstall github.com/ffuf/ffuf/v2@v2.3.0                               ffuf
goinstall github.com/lc/subjs@v1.0.1                                   subjs
goinstall github.com/003random/getJS/v2@v2.0.0                         getJS
goinstall github.com/projectdiscovery/urlfinder/cmd/urlfinder@v0.0.3   urlfinder
# --- v1.4.0 additions ---
goinstall github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.7.0        naabu
goinstall github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1 shuffledns
goinstall github.com/d3mondev/puredns/v2@v2.1.1                        puredns
goinstall github.com/projectdiscovery/asnmap/cmd/asnmap@v1.2.0         asnmap
goinstall github.com/projectdiscovery/mapcidr/cmd/mapcidr@v1.1.97       mapcidr
goinstall github.com/projectdiscovery/cdncheck/cmd/cdncheck@v1.4.0     cdncheck
goinstall github.com/projectdiscovery/uncover/cmd/uncover@v1.2.1       uncover
goinstall github.com/projectdiscovery/notify/cmd/notify@v1.0.7         notify
goinstall github.com/owasp-amass/amass/v4/...@v4.2.0                   amass
goinstall github.com/tomnomnom/assetfinder@v0.1.1                      assetfinder
goinstall github.com/PentestPad/subzy@v1.2.1                           subzy
goinstall github.com/sensepost/gowitness@v0.0.0-20261011045312-601c84367aaf                        gowitness
goinstall github.com/BishopFox/jsluice/cmd/jsluice@v0.0.0-20240110145140-0ddfab153e06              jsluice
goinstall github.com/gwen001/github-subdomains@v1.2.2                  github-subdomains
goinstall github.com/gwen001/github-endpoints@v1.2.2                   github-endpoints

# --- 4) pipx (isolated venvs) -> /usr/local/bin ---------------------------
export PIPX_HOME="$RECON_ROOT/pipx"
export PIPX_BIN_DIR="/usr/local/bin"
pipxinstall(){ # <pkg> [binname]
  local pkg="$1" name="${2:-$1}"
  if have "$name" && [ "$FORCE" != "1" ]; then ok "$name present"; return 0; fi
  if ! have pipx; then warn "pipx missing; skip $pkg"; return 1; fi
  log "pipx install $pkg"
  if pipx install "$pkg" >"/tmp/pipx_${name}.log" 2>&1; then ok "installed $name";
  else warn "FAILED pipx $pkg (tail: $(tail -n1 /tmp/pipx_${name}.log 2>/dev/null))"; fi
}
log "Installing Python (pipx) tooling..."
pipxinstall waymore
pipxinstall arjun
pipxinstall uro
pipxinstall dirsearch
pipxinstall xnLinkFinder
pipxinstall droopescan

# --- 5) git + dedicated venvs (explicit virtualenvs) ----------------------
install_git_venv(){ # <name> <repo> <entry.py>
  local name="$1" repo="$2" entry="$3"
  local dir="$RECON_ROOT/tools/$name"
  if [ -d "$dir/.git" ]; then
    (cd "$dir" && git pull --ff-only >/dev/null 2>&1 || true)
  else
    log "cloning $name"
    git clone --depth 1 "$repo" "$dir" >/dev/null 2>&1 || { warn "clone failed: $name"; return 1; }
  fi
  python3 -m venv "$dir/.venv" || { warn "venv create failed: $name"; return 1; }
  "$dir/.venv/bin/pip" install --quiet --upgrade pip wheel >/dev/null 2>&1 || true
  if [ -f "$dir/requirements.txt" ]; then
    "$dir/.venv/bin/pip" install --quiet -r "$dir/requirements.txt" >/dev/null 2>&1 \
      || warn "pip requirements failed: $name"
  fi
  cat >"/usr/local/bin/$name" <<WRAP
#!/usr/bin/env bash
exec "$dir/.venv/bin/python" "$dir/$entry" "\$@"
WRAP
  chmod +x "/usr/local/bin/$name"
  ok "installed $name (venv)"
}
log "Installing JS-analysis tooling (git + venv)..."
install_git_venv linkfinder   https://github.com/GerbenJavado/LinkFinder.git linkfinder.py
install_git_venv secretfinder https://github.com/m4ll0k/SecretFinder.git     SecretFinder.py
install_git_venv cloud_enum   https://github.com/initstring/cloud_enum.git   cloud_enum.py
install_git_venv cmseek       https://github.com/Tuhinshubhra/CMSeeK.git     cmseek.py
install_git_venv tookie-osint https://github.com/Alfredredbird/tookie-osint.git tookie-osint.py
if ! have dnsvalidator; then
  log "Installing dnsvalidator (pipx from git)..."
  pipx install "git+https://github.com/vortexau/dnsvalidator.git" >/dev/null 2>&1 \
    && ok "dnsvalidator installed" || warn "dnsvalidator install failed (non-fatal)."
fi
if ! have wpscan; then
  log "Installing wpscan (Ruby gem)..."
  gem install wpscan >/dev/null 2>&1 && ok "wpscan installed" \
    || warn "wpscan gem install failed (try: apt install wpscan). --active falls back to native probes."
fi
if ! have joomscan; then
  log "Installing OWASP joomscan (git clone)..."
  rm -rf /opt/recon/joomscan 2>/dev/null
  if git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/recon/joomscan >/dev/null 2>&1; then
    printf '#!/usr/bin/env bash\nexec perl /opt/recon/joomscan/joomscan.pl "$@"\n' > /usr/local/bin/joomscan
    chmod +x /usr/local/bin/joomscan && ok "joomscan installed" || warn "joomscan wrapper failed"
  else warn "joomscan clone failed (non-fatal)."; fi
fi
if ! have trufflehog; then
  log "Installing trufflehog (release binary; not go-installable)..."
  if curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
       | sh -s -- -b /usr/local/bin >/dev/null 2>&1 && have trufflehog; then
    ok "trufflehog installed"
  else warn "trufflehog install failed (non-fatal; secretfinder is primary)."; fi
fi

# --- 5b) extras: massdns (source) + findomain (release) -------------------
if ! have massdns; then
  log "Building massdns from source (DNS bruteforce backend)..."
  if git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns >/dev/null 2>&1 \
     && ( cd /tmp/massdns && make >/dev/null 2>&1 ) && [ -f /tmp/massdns/bin/massdns ]; then
    install -m 0755 /tmp/massdns/bin/massdns /usr/local/bin/massdns && ok "massdns installed" || warn "massdns install failed"
  else warn "massdns build failed; --brute will fall back to puredns if present."; fi
  rm -rf /tmp/massdns
fi
if ! have findomain; then
  log "Installing findomain (release binary)..."
  if curl -fsSL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/f.zip \
     && unzip -o /tmp/f.zip -d /tmp >/dev/null 2>&1 && [ -f /tmp/findomain ]; then
    install -m 0755 /tmp/findomain /usr/local/bin/findomain && ok "findomain installed" || warn "findomain install failed"
  else warn "findomain download failed (non-fatal)."; fi
  rm -f /tmp/f.zip /tmp/findomain
fi

# --- 5c) subfinder provider-config scaffold (OSINT API keys) ---------------
SFCFG="${HOME:-/root}/.config/subfinder/provider-config.yaml"
if [ ! -f "$SFCFG" ]; then
  mkdir -p "$(dirname "$SFCFG")" 2>/dev/null
  cat > "$SFCFG" <<'YAML'
# subfinder provider-config -- paste API keys to unlock premium passive sources.
# Remove the leading '#' and fill in keys you have (free tiers exist for many).
#virustotal: [ "YOUR_VT_API_KEY" ]
#securitytrails: [ "YOUR_KEY" ]
#censys: [ "API_ID:API_SECRET" ]
#shodan: [ "YOUR_KEY" ]
#fullhunt: [ "YOUR_KEY" ]
#netlas: [ "YOUR_KEY" ]
#chaos: [ "YOUR_KEY" ]
#github: [ "YOUR_GITHUB_PAT" ]
YAML
  ok "wrote subfinder provider-config scaffold: $SFCFG"
fi

# --- 6) optional heavy assets ---------------------------------------------
if [ "$INCLUDE_HEAVY" = "1" ]; then
  log "Heavy mode: SecLists + nuclei-templates + feroxbuster"
  if [ ! -d "$RECON_ROOT/wordlists/SecLists/.git" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
      "$RECON_ROOT/wordlists/SecLists" >/dev/null 2>&1 \
      && ok "SecLists cloned" || warn "SecLists clone failed"
  else ok "SecLists present"; fi
  if have nuclei; then
    nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated" \
      || warn "nuclei template update failed"
  fi
  if ! have feroxbuster; then
    log "Installing feroxbuster..."
    if curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh -o /tmp/ferox.sh; then
      ( cd /usr/local/bin && bash /tmp/ferox.sh >/dev/null 2>&1 ) \
        && ok "feroxbuster installed" || warn "feroxbuster install failed"
    fi
  fi
else
  log "Skipping heavy assets (-IncludeHeavyTools enables SecLists / nuclei-templates / feroxbuster)."
fi

# --- 7) env files + marker -------------------------------------------------
cat >"$RECON_ROOT/recon.env" <<ENV
# Source this for an interactive recon shell.
export RECON_ROOT="$RECON_ROOT"
export PATH="/usr/local/go/bin:/usr/local/bin:\$PATH"
export GOPATH="$RECON_ROOT/go"
export SECLISTS="$RECON_ROOT/wordlists/SecLists"
ENV
cat >/etc/profile.d/recon.sh <<'PROF'
export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"
PROF
chmod 0644 /etc/profile.d/recon.sh
date > "$RECON_ROOT/.provisioned"

# --- 8) verification -------------------------------------------------------
log "Verifying installed tools..."
PRESENT=""; MISSING=""
for t in gau waybackurls anew unfurl qsreplace gf httpx-toolkit katana subfinder dnsx \
         tlsx alterx nuclei hakrawler gospider ffuf subjs getJS urlfinder waymore \
         arjun uro dirsearch xnLinkFinder linkfinder secretfinder \
         naabu shuffledns puredns massdns asnmap mapcidr cdncheck uncover notify \
         amass assetfinder findomain subzy gowitness jsluice trufflehog \
         github-subdomains github-endpoints cloud_enum dnsvalidator \
         wpscan droopescan joomscan cmseek whatweb \
         python3 go; do
  if have "$t"; then PRESENT="$PRESENT $t"; else MISSING="$MISSING $t"; fi
done
echo
ok "PRESENT:$PRESENT"
if [ -n "$MISSING" ]; then warn "MISSING:$MISSING"; else ok "All expected tools present."; fi
echo
ok "Provisioning complete. Toolkit root: $RECON_ROOT"
'@

# ===========================================================================
# Main flow
# ===========================================================================
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host " EASM URL-Enumeration Environment Setup (WSL2)" -ForegroundColor Magenta
Write-Host " Authorization: only assess assets you own or may legally test." -ForegroundColor Magenta
Write-Host "================================================================" -ForegroundColor Magenta

# --- prerequisite: Windows build ------------------------------------------
try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuildNumber
    Write-Step "Windows build: $build ($($cv.ProductName))"
    if ($build -lt 19041) {
        Write-Warn2 "WSL2 needs Windows 10 build 19041 (2004) or later, or Windows 11."
        Write-Warn2 "Detected build $build. Update Windows, then re-run."
    }
} catch { Write-Warn2 "Could not read Windows build number; continuing." }

$wslReady = $false

if ($SkipWslInstall) {
    Write-Step "Skipping WSL install (per -SkipWslInstall)."
} else {
    Write-Step "Checking WSL..."
    if (Test-WslPresent) {
        Write-Ok "WSL is present."
        try { & wsl.exe --update *> $null } catch {}
        try { & wsl.exe --set-default-version 2 *> $null } catch {}
    } else {
        Write-Warn2 "WSL is not installed/enabled."
        if (-not (Test-Admin)) {
            Write-ErrX "Administrator rights are required to install WSL."
            Write-ErrX "Re-run this script from an ELEVATED PowerShell:"
            Write-Host  "    Start-Process powershell -Verb RunAs" -ForegroundColor White
            exit 1
        }
        Write-Step "Installing WSL (this may require a reboot)..."
        try {
            & wsl.exe --install --no-launch
        } catch {
            Write-Warn2 "'wsl --install --no-launch' failed; trying legacy feature enable..."
            & dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
            & dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
        }
        Write-Warn2 "WSL components were installed. A REBOOT is usually required."
        Write-Warn2 "Reboot, then run this script again to finish provisioning."
        exit 3
    }
}

# --- ensure distro present -------------------------------------------------
$distros = Get-WslDistros
Write-Step "Installed distros: $([string]::Join(', ', $distros))"

if ($distros -notcontains $Distro) {
    if ($SkipWslInstall) {
        Write-ErrX "Distro '$Distro' not found and -SkipWslInstall was set. Install it first:"
        Write-Host "    wsl --install -d $Distro" -ForegroundColor White
        exit 1
    }
    Write-Step "Installing distro '$Distro'..."
    try {
        & wsl.exe --install -d $Distro --no-launch
    } catch {
        Write-ErrX "Failed to install distro '$Distro'. Install manually: wsl --install -d $Distro"
        exit 1
    }
    Start-Sleep -Seconds 3
}

# --- ensure distro is initialized/ready ------------------------------------
Write-Step "Initializing '$Distro' (first launch as root)..."
$ready = $false
for ($i = 0; $i -lt 5; $i++) {
    if (Test-DistroReady $Distro) { $ready = $true; break }
    Start-Sleep -Seconds 4
}
if (-not $ready) {
    Write-ErrX "Distro '$Distro' is not responding. If WSL was just installed, REBOOT and re-run."
    Write-ErrX "Otherwise launch it once manually ('wsl -d $Distro') and re-run this script."
    exit 3
}
Write-Ok "Distro '$Distro' is ready."

# --- run provisioning ------------------------------------------------------
Write-Step "Provisioning toolkit inside '$Distro' (root)..."
$heavy = if ($IncludeHeavyTools) { '1' } else { '0' }
$force = if ($Force) { '1' } else { '0' }

$winProv = Join-Path $env:TEMP ("recon-provision-{0}.sh" -f ([guid]::NewGuid().ToString('N')))
Write-LfFile -Path $winProv -Text $ProvisionScript
$wslProv = ConvertTo-WslPath $winProv

$provExit = 0
try {
    & wsl.exe -d $Distro -u root -- env `
        RECON_ROOT="$InstallRoot" INCLUDE_HEAVY="$heavy" FORCE="$force" `
        bash "$wslProv"
    $provExit = $LASTEXITCODE
} finally {
    Remove-Item $winProv -ErrorAction SilentlyContinue
}
if ($provExit -ne 0) {
    Write-Warn2 "Provisioning returned exit code $provExit. Review the output above; some tools may be missing."
} else {
    Write-Ok "Provisioning finished."
}

# --- install the companion operational script ------------------------------
$localRun = Join-Path $PSScriptRoot 'run-recon.sh'
if (Test-Path $localRun) {
    Write-Step "Installing run-recon.sh into the distro..."
    $runText = Get-Content -Raw -Path $localRun
    $winRun  = Join-Path $env:TEMP 'run-recon.sh'
    Write-LfFile -Path $winRun -Text $runText
    $wslRun = ConvertTo-WslPath $winRun
    $bashCmd = "mkdir -p '$InstallRoot/bin'; cp '$wslRun' '$InstallRoot/bin/run-recon.sh'; chmod +x '$InstallRoot/bin/run-recon.sh'; ln -sf '$InstallRoot/bin/run-recon.sh' /usr/local/bin/run-recon"
    try {
        & wsl.exe -d $Distro -u root -- bash -c $bashCmd
        Write-Ok "Installed: $InstallRoot/bin/run-recon.sh  (command: run-recon)"
    } catch {
        Write-Warn2 "Could not auto-install run-recon.sh. Copy it manually into WSL."
    } finally {
        Remove-Item $winRun -ErrorAction SilentlyContinue
    }
} else {
    Write-Warn2 "run-recon.sh not found next to this script ($PSScriptRoot)."
    Write-Warn2 "Place run-recon.sh in the same folder and re-run, or copy it into WSL yourself."
}

# --- final guidance --------------------------------------------------------
Write-Host "`n================================================================" -ForegroundColor Green
Write-Ok "Setup complete."
Write-Host @"

Next steps (inside WSL):

  wsl -d $Distro

  # create your scope file (one domain per line)
  printf '%s\n' example.com api.example.com > domains.txt

  # run the enumeration (passive + crawl + validate by default)
  run-recon -i domains.txt -o results.csv

  # faster / quieter variants:
  run-recon -i domains.txt --passive-only          # no traffic to targets
  run-recon -i domains.txt --subs --deep -t 10     # subdomains + waymore, 10 parallel

The CSV is written inside the distro. Open it from Windows via:
  \\wsl.localhost\$Distro\home\<user>\results.csv     (or use a path under /mnt/c/...)

Re-run this setup any time; it is idempotent. Use -Force to upgrade tools,
-IncludeHeavyTools to add SecLists + nuclei-templates + feroxbuster.
"@ -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Green
