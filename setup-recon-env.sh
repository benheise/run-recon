#!/usr/bin/env bash
#
# setup-recon-env.sh  --  Linux-native equivalent of Setup-ReconEnv.ps1
#
# Provisions an open-source URL-enumeration / External Attack Surface Management
# (EASM) toolchain on a Debian/Ubuntu host (a WSL2 Ubuntu distro, a VM, a
# bare-metal box, or a container). Because bash already runs *inside* the target
# Linux environment, the WSL-bootstrapping layer of the PowerShell version
# (Windows build checks, `wsl --install`, DISM, distro initialization) does not
# apply and is intentionally omitted. Everything else is faithfully ported.
#
# Installs system-wide under /opt/recon, with binaries/shims on PATH via
# /usr/local/bin:
#   - apt/dnf/pacman base packages (git, python3-venv, build tools, jq, ldnsutils for the lab's signed zones,
#     python3-cryptography for the lab's TLS fixture certificates, libpcap, postgresql-client...)
#   - Go toolchain (pinned) -> /usr/local/go
#   - Go tools -> /usr/local/bin: gau, waybackurls, httpx, katana, subfinder,
#     dnsx, tlsx, alterx, nuclei, hakrawler, gospider, ffuf, subjs, getJS,
#     urlfinder, anew, unfurl, qsreplace, gf
#       (dnsx = --resolve validation gate; tlsx = --certs SAN/CN harvest;
#        alterx = --permute host permutations in run-recon.sh)
#   - pipx (isolated venvs) -> /usr/local/bin: waymore, arjun, uro, dirsearch,
#     xnLinkFinder
#   - git + dedicated venvs: LinkFinder, SecretFinder
#   - (optional, --include-heavy) SecLists wordlists, nuclei-templates, feroxbuster
# Then installs Outcrop (outcrop.sh, found next to this script) to /opt/recon/bin/ and
# symlinks it to /usr/local/bin/outcrop; run-recon.sh, its former name, is installed
# beside it as a wrapper and stays available as /usr/local/bin/run-recon.
#
# Run as root, or as a user with sudo (privileged steps are sudo-wrapped).
# NOTE: no `set -e` -- one failed tool must not abort the whole run; each
# install is individually guarded.
#
# Authorization: only enumerate assets your organization owns or may assess.
#
set -uo pipefail

VERSION="1.8.0"

# ---------------------------------------------------------------------------
# Defaults (equivalent to the PowerShell params). -Distro / -SkipWslInstall
# have no meaning on a running Linux host and are dropped.
# ---------------------------------------------------------------------------
INSTALL_ROOT="/opt/recon"
GO_VERSION="1.24.5"
INCLUDE_HEAVY=0
FORCE=0
DRY_RUN=0
SETUP_DB=1          # create the recon PostgreSQL cache DB (reuse msf's postgres); --no-db to skip
SETUP_DNS_CACHE=0   # set up a local unbound caching resolver to cut DNS-stage timeouts (--dns-cache)

GO_BIN="/usr/local/go/bin/go"
# Ensure Go + local bin are visible to *this* shell's checks/invocations.
export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"

# ---------------------------------------------------------------------------
# Tool inventories (module|binname ; pkg ; name|repo|entry)
# ---------------------------------------------------------------------------
# Versions are PINNED. A tool's output format can change between releases without
# notice (httpx 1.6 moved the IP into host_ip; dnsx 1.3 stopped printing NXDOMAIN rows
# for -rcode filters), and run-recon parses that output. The ProjectDiscovery tools
# marked "lab" were checked against the benchmark lab (bench-run-recon.sh) at exactly
# these versions. To upgrade: RECON_TOOLS_LATEST=1 ./setup-recon-env.sh --force, then
# re-run the lab (`bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6"`) before
# trusting the new versions, and update the pins.
GO_TOOLS=(
  "github.com/lc/gau/v2/cmd/gau@v2.2.4|gau"
  "github.com/tomnomnom/waybackurls@v0.1.0|waybackurls"
  "github.com/tomnomnom/anew@v0.1.1|anew"
  "github.com/tomnomnom/unfurl@v0.4.3|unfurl"
  "github.com/tomnomnom/qsreplace@v0.0.3|qsreplace"
  "github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5|gf"
  # NOTE: httpx is provisioned separately as 'httpx-toolkit' (see install_httpx) to
  # avoid the python3-httpx clash on /usr/bin/httpx; run-recon defaults to that name.
  "github.com/projectdiscovery/katana/cmd/katana@v1.8.0|katana"                  # lab
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0|subfinder"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1|dnsx"                     # lab
  "github.com/projectdiscovery/tlsx/cmd/tlsx@v1.4.0|tlsx"                     # lab
  "github.com/projectdiscovery/alterx/cmd/alterx@v0.1.0|alterx"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1|nuclei"              # lab (-ni / -iserver)
  "github.com/hakluke/hakrawler@v0.0.0-20260805040537-52a16fe61bd1|hakrawler"
  "github.com/jaeles-project/gospider@v1.1.6|gospider"
  "github.com/ffuf/ffuf/v2@v2.3.0|ffuf"
  "github.com/lc/subjs@v1.0.1|subjs"
  "github.com/003random/getJS/v2@v2.0.0|getJS"
  "github.com/projectdiscovery/urlfinder/cmd/urlfinder@v0.0.3|urlfinder"
  # --- v1.4.0 additions: discovery + defensive tooling ---
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.7.0|naabu"          # port discovery (needs libpcap-dev)
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1|shuffledns"  # DNS bruteforce (needs massdns)
  "github.com/d3mondev/puredns/v2@v2.1.1|puredns"                       # DNS bruteforce alt (needs massdns)
  "github.com/projectdiscovery/asnmap/cmd/asnmap@v1.2.0|asnmap"         # ASN -> CIDR (needs PDCP_API_KEY; lab)
  "github.com/projectdiscovery/mapcidr/cmd/mapcidr@v1.1.97|mapcidr"      # CIDR aggregate (lab)
  "github.com/projectdiscovery/cdncheck/cmd/cdncheck@v1.4.0|cdncheck"   # CDN/WAF provider tagging
  "github.com/projectdiscovery/uncover/cmd/uncover@v1.2.1|uncover"      # Shodan/Censys/Fofa pivot
  "github.com/projectdiscovery/notify/cmd/notify@v1.0.7|notify"         # monitoring notifications
  # --- v1.20 additions (Batch 3) ---
  "github.com/projectdiscovery/cloudlist/cmd/cloudlist@v1.5.1|cloudlist" # cloud inventory diff (--cloudlist)
  "github.com/projectdiscovery/tldfinder/cmd/tldfinder@v0.0.2|tldfinder" # TLD variants (--tld-variants)
  "github.com/projectdiscovery/vulnx/v2/cmd/vulnx@v2.0.2|vulnx"         # product advisories (--vulnx)
  "github.com/owasp-amass/amass/v4/...@v4.2.0|amass"                    # passive subdomains
  "github.com/tomnomnom/assetfinder@v0.1.1|assetfinder"                 # passive subdomains
  "github.com/PentestPad/subzy@v1.2.1|subzy"                            # subdomain takeover (lab)
  "github.com/sensepost/gowitness@v0.0.0-20261011045312-601c84367aaf|gowitness"                     # screenshots (httpx -ss fallback)
  "github.com/BishopFox/jsluice/cmd/jsluice@v0.0.0-20240110145140-0ddfab153e06|jsluice"             # JS endpoint extraction alt
  # NOTE: trufflehog is NOT go-installable (its go.mod uses replace directives, which
  # `go install pkg@version` rejects); it is installed from its release binary in install_extras.
  "github.com/gwen001/github-subdomains@v1.2.2|github-subdomains"       # subdomains leaked in public code
  "github.com/gwen001/github-endpoints@v1.2.2|github-endpoints"         # endpoints leaked in public code
)
PIPX_TOOLS=( "waymore" "arjun" "uro" "dirsearch" "xnLinkFinder" "droopescan" )
GITVENV_TOOLS=(
  "linkfinder|https://github.com/GerbenJavado/LinkFinder.git|linkfinder.py"
  "secretfinder|https://github.com/m4ll0k/SecretFinder.git|SecretFinder.py"
  "cloud_enum|https://github.com/initstring/cloud_enum.git|cloud_enum.py"   # S3/Azure/GCP bucket enum
  "cmseek|https://github.com/Tuhinshubhra/CMSeeK.git|cmseek.py"             # multi-CMS detection/enum
  "tookie-osint|https://github.com/Alfredredbird/tookie-osint.git|tookie-osint.py"  # social-media account discovery (--social)
)

# ---------------------------------------------------------------------------
# Logging (tty-aware colours; logs to stderr so stdout stays clean)
# ---------------------------------------------------------------------------
_c(){ [ -t 2 ] && printf '%s' "$1" || printf ''; }
log(){  printf '%s[*]%s %s\n' "$(_c $'\033[1;34m')" "$(_c $'\033[0m')" "$*" >&2; }
ok(){   printf '%s[+]%s %s\n' "$(_c $'\033[1;32m')" "$(_c $'\033[0m')" "$*" >&2; }
warn(){ printf '%s[!]%s %s\n' "$(_c $'\033[1;33m')" "$(_c $'\033[0m')" "$*" >&2; }
err(){  printf '%s[x]%s %s\n' "$(_c $'\033[1;31m')" "$(_c $'\033[0m')" "$*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# as_root <cmd...>  -- run privileged commands directly if root, else via sudo
# ---------------------------------------------------------------------------
as_root(){
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
OS_ID="unknown"; OS_PRETTY="unknown"; PKG_MGR="none"
detect_os(){
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
  fi
  if   have apt-get; then PKG_MGR="apt"
  elif have dnf;     then PKG_MGR="dnf"
  elif have pacman;  then PKG_MGR="pacman"
  else PKG_MGR="none"; fi
}
is_wsl(){
  grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease 2>/dev/null \
    || grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}

usage(){
  cat >&2 <<EOF
setup-recon-env.sh v$VERSION  --  provision the EASM URL-enumeration toolkit (Linux)

USAGE:
  ./setup-recon-env.sh [options]          # as root, or with sudo available

OPTIONS:
  -r, --install-root DIR   Install prefix for the toolkit   (default: $INSTALL_ROOT)
      --go-version X.Y.Z   Pinned Go version to install     (default: $GO_VERSION)
      --include-heavy      Also install SecLists (~1GB+), nuclei-templates, feroxbuster
      --heavy              Alias for --include-heavy
  -f, --force              Reinstall/upgrade tools even if present
      --no-db              Skip creating the recon PostgreSQL cache DB (default: create it,
                           reusing the local msf/postgres service; see recon-db.sh)
      --dns-cache          Also set up a local unbound caching resolver (127.0.0.1) and a
                           resolvers file, to cut DNS-stage timeouts (use --resolvers at runtime)
  -n, --dry-run            Detect environment and print the plan; make no changes
  -h, --help               Show this help
      --version            Show version

NOTES:
  - Debian/Ubuntu is the primary target (apt). dnf/pacman are best-effort for
    base packages; the Go/pipx/git tool layers are distro-agnostic.
  - Run from an ELEVATED shell (root) or as a sudo-capable user.
  - Re-running is safe (idempotent); --force upgrades everything.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -r|--install-root) INSTALL_ROOT="${2:?}"; shift 2;;
    --go-version)      GO_VERSION="${2:?}"; shift 2;;
    --include-heavy|--heavy) INCLUDE_HEAVY=1; shift;;
    -f|--force)        FORCE=1; shift;;
    --no-db|--skip-db) SETUP_DB=0; shift;;
    --dns-cache)       SETUP_DNS_CACHE=1; shift;;
    -n|--dry-run)      DRY_RUN=1; shift;;
    -h|--help)         usage; exit 0;;
    --version)         echo "setup-recon-env.sh v$VERSION"; exit 0;;
    *) err "Unknown argument: $1"; usage; exit 2;;
  esac
done

# ===========================================================================
# Banner
# ===========================================================================
echo >&2
log "================================================================"
log " EASM URL-Enumeration Environment Setup (Linux/bash)"
log " Authorization: only assess assets you own or may legally test."
log "================================================================"

# ---------------------------------------------------------------------------
# Platform + privilege prerequisites
# ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Linux" ]; then
  err "This installer targets Linux (incl. WSL2). Detected: $(uname -s)."
  err "On macOS/Windows use the appropriate native workflow instead."
  exit 1
fi

detect_os
WSL="no"; is_wsl && WSL="yes"

if [ "$(id -u)" -ne 0 ]; then
  if ! have sudo; then
    err "Not running as root and 'sudo' was not found. Re-run as root."
    exit 1
  fi
  if [ "$DRY_RUN" != "1" ]; then
    log "Not root; using sudo for privileged steps (may prompt for your password)."
    sudo -v || { err "sudo authentication failed."; exit 1; }
  fi
fi

RUNNER_FOUND="no"; [ -f "$SCRIPT_DIR/outcrop.sh" ] && RUNNER_FOUND="yes"

# ---------------------------------------------------------------------------
# Dry-run: print the plan and exit without mutating anything
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = "1" ]; then
  log "---------------- DRY RUN (no changes) ----------------"
  log " OS               : $OS_PRETTY (id=$OS_ID)"
  log " Package manager  : $PKG_MGR"
  log " Inside WSL       : $WSL"
  log " Privilege        : $([ "$(id -u)" -eq 0 ] && echo root || echo "sudo")"
  log " Install root     : $INSTALL_ROOT"
  log " Go version       : $GO_VERSION"
  log " Include heavy    : $([ "$INCLUDE_HEAVY" = 1 ] && echo yes || echo no)"
  log " Force            : $([ "$FORCE" = 1 ] && echo yes || echo no)"
  log " outcrop.sh       : $RUNNER_FOUND ($SCRIPT_DIR/outcrop.sh; run-recon.sh is its wrapper)"
  log " companion scripts: generate-report.sh=$([ -f "$SCRIPT_DIR/generate-report.sh" ] && echo yes || echo no) recon-db.sh=$([ -f "$SCRIPT_DIR/recon-db.sh" ] && echo yes || echo no)"
  log " recon DB setup   : $([ "$SETUP_DB" = 1 ] && echo "yes (recon-db.sh init; dedicated 'recon' DB, msfdb backup)" || echo "no (--no-db)")"
  log " DNS cache        : $([ "$SETUP_DNS_CACHE" = 1 ] && echo "yes (unbound @127.0.0.1)" || echo "no (--dns-cache to enable)")"
  log " Go tools (${#GO_TOOLS[@]}) : $(for t in "${GO_TOOLS[@]}"; do printf '%s ' "${t##*|}"; done)"
  log " pipx tools (${#PIPX_TOOLS[@]}): ${PIPX_TOOLS[*]}"
  log " git+venv (${#GITVENV_TOOLS[@]})  : $(for t in "${GITVENV_TOOLS[@]}"; do printf '%s ' "${t%%|*}"; done)"
  [ "$PKG_MGR" = "none" ] && warn "No supported package manager detected; base packages would be skipped."
  log "------------------------------------------------------"
  exit 0
fi

if [ "$PKG_MGR" = "none" ]; then
  warn "No supported package manager (apt/dnf/pacman) detected."
  warn "Install these manually before proceeding: git curl python3 python3-venv"
  warn "pipx jq build tools libpcap headers. Continuing (tool installs may fail)."
fi

as_root mkdir -p "$INSTALL_ROOT/go" "$INSTALL_ROOT/pipx" "$INSTALL_ROOT/tools" \
                 "$INSTALL_ROOT/wordlists" "$INSTALL_ROOT/bin"

# ===========================================================================
# 1) base packages
# ===========================================================================
install_base_packages(){
  case "$PKG_MGR" in
    apt)
      log "apt: update + base packages (this can take a few minutes)..."
      as_root apt-get update -y || warn "apt-get update reported errors"
      as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git curl wget unzip zip ca-certificates build-essential pkg-config \
        python3 python3-venv python3-pip pipx python3-cryptography \
        jq dnsutils ldnsutils whois libpcap-dev gcc make \
        ruby ruby-dev whatweb \
        postgresql-client \
        || warn "some apt packages failed to install"
      as_root update-ca-certificates 2>/dev/null || true
      ;;
    dnf)
      log "dnf: installing base packages..."
      as_root dnf install -y \
        git curl wget unzip zip ca-certificates pkgconf-pkg-config \
        python3 python3-pip pipx python3-cryptography jq bind-utils ldns-utils whois libpcap-devel gcc make postgresql \
        ruby ruby-devel \
        || warn "some dnf packages failed to install"
      as_root dnf groupinstall -y "Development Tools" 2>/dev/null || true
      ;;
    pacman)
      log "pacman: installing base packages..."
      as_root pacman -Sy --noconfirm --needed \
        git curl wget unzip zip ca-certificates base-devel pkgconf \
        python python-pip python-pipx python-cryptography jq bind ldns whois libpcap gcc make \
        ruby whatweb \
        || warn "some pacman packages failed to install"
      ;;
    *) warn "Skipping base packages (no package manager).";;
  esac
}
install_base_packages

# ===========================================================================
# 2) Go toolchain (pinned) -> /usr/local/go
# ===========================================================================
install_go(){
  if [ -x "$GO_BIN" ] && [ "$FORCE" != "1" ]; then
    local gv gmin
    gv="$("$GO_BIN" version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -n1 | sed 's/go//')"
    gmin="${gv#*.}"; gv="${gv%%.*}"
    # GOTOOLCHAIN=auto (per-module toolchain download) needs Go >= 1.21; older Go
    # can't build tools that require newer language versions, so upgrade it.
    if [ -n "$gv" ] && { [ "$gv" -gt 1 ] || { [ "$gv" -eq 1 ] && [ "${gmin:-0}" -ge 21 ]; }; }; then
      ok "Go present: $($GO_BIN version 2>/dev/null)"; return 0
    fi
    warn "Go ${gv:-?}.${gmin:-?} is too old for per-module toolchains; upgrading to ${GO_VERSION}."
  fi
  local arch goarch tgz url
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)  goarch=amd64 ;;
    aarch64|arm64) goarch=arm64 ;;
    armv7l|armv6l) goarch=armv6l ;;
    *)             goarch=amd64 ;;
  esac
  tgz="/tmp/go${GO_VERSION}.linux-${goarch}.tar.gz"
  url="https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz"
  log "Downloading Go ${GO_VERSION} (${goarch})..."
  if curl -fsSL "$url" -o "$tgz"; then
    as_root rm -rf /usr/local/go
    if as_root tar -C /usr/local -xzf "$tgz"; then ok "Go installed to /usr/local/go"
    else warn "Go extract failed"; fi
  else
    warn "Go download failed ($url). Go-based tools will be skipped."
  fi
}
install_go

# ===========================================================================
# 3) Go tools -> /usr/local/bin
# ===========================================================================
goinstall(){ # <module> <binname>
  local mod="$1" name="$2"
  # RECON_TOOLS_LATEST=1: ignore the pin (for a deliberate upgrade; re-run the lab after)
  [ "${RECON_TOOLS_LATEST:-0}" = "1" ] && mod="${mod%@*}@latest"
  if have "$name" && [ "$FORCE" != "1" ]; then ok "$name present"; return 0; fi
  if [ ! -x "$GO_BIN" ]; then warn "go missing; skip $name"; return 1; fi
  log "go install $name"
  if as_root env GOBIN=/usr/local/bin GOPATH="$INSTALL_ROOT/go" \
        GOMODCACHE="$INSTALL_ROOT/go/pkg/mod" GOTOOLCHAIN=auto \
        "$GO_BIN" install "$mod" >"/tmp/go_${name}.log" 2>&1; then
    ok "installed $name"
  else
    warn "FAILED $name (tail: $(tail -n1 "/tmp/go_${name}.log" 2>/dev/null))"
  fi
}
log "Installing Go-based tooling..."
for t in "${GO_TOOLS[@]}"; do
  goinstall "${t%%|*}" "${t##*|}"
done

# ---------------------------------------------------------------------------
# httpx-toolkit: run-recon calls ProjectDiscovery httpx as 'httpx-toolkit' to
# avoid the python3-httpx binary that owns /usr/bin/httpx on Kali. Provision it
# by that name explicitly. We do NOT gate on `have httpx` (that would match the
# python client and wrongly skip). Prefer an existing httpx-toolkit (Kali apt);
# otherwise go-install PD httpx to /usr/local/bin and symlink httpx-toolkit -> it.
# ---------------------------------------------------------------------------
HTTPX_PIN="v1.12.0"   # lab-verified (see the pinning note above GO_TOOLS)
install_httpx(){
  if have httpx-toolkit && [ "$FORCE" != "1" ]; then ok "httpx-toolkit present (PD httpx)"; return 0; fi
  if [ ! -x "$GO_BIN" ]; then warn "go missing; cannot install httpx-toolkit"; return 1; fi
  log "go install httpx (exposed as httpx-toolkit)"
  if as_root env GOBIN=/usr/local/bin GOPATH="$INSTALL_ROOT/go" \
        GOMODCACHE="$INSTALL_ROOT/go/pkg/mod" GOTOOLCHAIN=auto \
        "$GO_BIN" install "github.com/projectdiscovery/httpx/cmd/httpx@$( [ "${RECON_TOOLS_LATEST:-0}" = "1" ] && echo latest || echo "$HTTPX_PIN" )" >/tmp/go_httpx.log 2>&1; then
    as_root ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit
    ok "installed httpx-toolkit (-> /usr/local/bin/httpx)"
  else
    warn "FAILED httpx-toolkit (tail: $(tail -n1 /tmp/go_httpx.log 2>/dev/null))"
  fi
}
install_httpx

# ===========================================================================
# 4) pipx (isolated venvs) -> /usr/local/bin
# ===========================================================================
pipxinstall(){ # <pkg> [binname]
  local pkg="$1" name="${2:-$1}"
  if have "$name" && [ "$FORCE" != "1" ]; then ok "$name present"; return 0; fi
  if ! have pipx; then warn "pipx missing; skip $pkg"; return 1; fi
  log "pipx install $pkg"
  if as_root env PIPX_HOME="$INSTALL_ROOT/pipx" PIPX_BIN_DIR=/usr/local/bin \
        pipx install "$pkg" >"/tmp/pipx_${name}.log" 2>&1; then
    ok "installed $name"
  else
    warn "FAILED pipx $pkg (tail: $(tail -n1 "/tmp/pipx_${name}.log" 2>/dev/null))"
  fi
}
log "Installing Python (pipx) tooling..."
for p in "${PIPX_TOOLS[@]}"; do
  pipxinstall "$p"
done

# ===========================================================================
# 5) git + dedicated venvs (explicit virtualenvs) with /usr/local/bin wrappers
# ===========================================================================
install_git_venv(){ # <name> <repo> <entry.py>
  local name="$1" repo="$2" entry="$3"
  local dir="$INSTALL_ROOT/tools/$name"
  if [ -d "$dir/.git" ]; then
    as_root git -C "$dir" pull --ff-only >/dev/null 2>&1 || true
  else
    log "cloning $name"
    as_root git clone --depth 1 "$repo" "$dir" >/dev/null 2>&1 \
      || { warn "clone failed: $name"; return 1; }
  fi
  as_root python3 -m venv "$dir/.venv" || { warn "venv create failed: $name"; return 1; }
  as_root "$dir/.venv/bin/pip" install --quiet --upgrade pip wheel >/dev/null 2>&1 || true
  if [ -f "$dir/requirements.txt" ]; then
    as_root "$dir/.venv/bin/pip" install --quiet -r "$dir/requirements.txt" >/dev/null 2>&1 \
      || warn "pip requirements failed: $name"
  fi
  as_root tee "/usr/local/bin/$name" >/dev/null <<WRAP
#!/usr/bin/env bash
exec "$dir/.venv/bin/python" "$dir/$entry" "\$@"
WRAP
  as_root chmod +x "/usr/local/bin/$name"
  ok "installed $name (venv)"
}
log "Installing JS-analysis tooling (git + venv)..."
for t in "${GITVENV_TOOLS[@]}"; do
  IFS='|' read -r gname grepo gentry <<<"$t"
  install_git_venv "$gname" "$grepo" "$gentry"
done

# ===========================================================================
# 5b) extras that are not go-install/pip: massdns (source) + findomain (release)
# ===========================================================================
install_extras(){
  # massdns: DNS bruteforce backend required by shuffledns/puredns (--brute).
  if ! have massdns; then
    log "Building massdns from source (DNS bruteforce backend)..."
    _md="$(mktemp -d)"
    if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$_md/massdns" >/dev/null 2>&1 \
       && ( cd "$_md/massdns" && make >/dev/null 2>&1 ) && [ -f "$_md/massdns/bin/massdns" ]; then
      as_root install -m 0755 "$_md/massdns/bin/massdns" /usr/local/bin/massdns \
        && ok "massdns installed" || warn "massdns install failed"
    else
      warn "massdns build failed (need git+make+gcc); --brute will use puredns if available."
    fi
    rm -rf "$_md"
  else
    ok "massdns present"
  fi
  # findomain: supplementary passive subdomain source (prebuilt release binary).
  if ! have findomain; then
    log "Installing findomain (release binary)..."
    _fd="$(mktemp -d)"
    if curl -fsSL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o "$_fd/f.zip" \
       && unzip -o "$_fd/f.zip" -d "$_fd" >/dev/null 2>&1 && [ -f "$_fd/findomain" ]; then
      as_root install -m 0755 "$_fd/findomain" /usr/local/bin/findomain \
        && ok "findomain installed" || warn "findomain install failed"
    else
      warn "findomain download failed (non-fatal; subfinder/amass/assetfinder still cover passive subs)."
    fi
    rm -rf "$_fd"
  else
    ok "findomain present"
  fi
  # dnsvalidator: validate public resolvers for a fresh, fast resolver list (--refresh-resolvers).
  if ! have dnsvalidator; then
    if have pipx; then
      log "Installing dnsvalidator (pipx from git)..."
      pipx install "git+https://github.com/vortexau/dnsvalidator.git" >/dev/null 2>&1 \
        && ok "dnsvalidator installed" || warn "dnsvalidator install failed (non-fatal; --refresh-resolvers will no-op)."
    else
      warn "pipx missing; skipping dnsvalidator."
    fi
  else
    ok "dnsvalidator present"
  fi
  # wpscan: WordPress scanner (Ruby gem). Kali ships it via apt; gem is portable.
  if ! have wpscan; then
    if have gem; then
      log "Installing wpscan (Ruby gem; can take a few minutes)..."
      as_root gem install wpscan >/dev/null 2>&1 && ok "wpscan installed" \
        || warn "wpscan gem install failed (try: sudo apt install wpscan). --active falls back to native WP probes."
    else
      warn "ruby/gem missing; skipping wpscan (--active uses native WP probes + nuclei instead)."
    fi
  else
    ok "wpscan present"
  fi
  # joomscan: OWASP Joomla scanner (Perl). Clone + wrapper.
  if ! have joomscan; then
    if have perl; then
      log "Installing OWASP joomscan (git clone)..."
      as_root rm -rf /opt/recon/joomscan 2>/dev/null || true
      if as_root git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/recon/joomscan >/dev/null 2>&1; then
        printf '#!/usr/bin/env bash\nexec perl /opt/recon/joomscan/joomscan.pl "$@"\n' | as_root tee /usr/local/bin/joomscan >/dev/null
        as_root chmod +x /usr/local/bin/joomscan && ok "joomscan installed" || warn "joomscan wrapper failed"
      else
        warn "joomscan clone failed (non-fatal; --active uses native Joomla probes + nuclei)."
      fi
    else
      warn "perl missing; skipping joomscan."
    fi
  else
    ok "joomscan present"
  fi
  # trufflehog: secret scanning (secretfinder fallback). NOT go-installable (replace
  # directives in its go.mod), so use the official release-binary install script.
  if ! have trufflehog; then
    log "Installing trufflehog (release binary via official install script)..."
    if curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
         | as_root sh -s -- -b /usr/local/bin >/dev/null 2>&1 && have trufflehog; then
      ok "trufflehog installed ($(trufflehog --version 2>&1 | head -n1))"
    else
      warn "trufflehog install failed (non-fatal; secretfinder is the primary secret scanner)."
    fi
  else
    ok "trufflehog present"
  fi
}
install_extras

# ===========================================================================
# 5b) subfinder provider-config scaffold (OSINT API keys).
# Most premium OSINT sources (Censys, Shodan, VirusTotal, SecurityTrails,
# FullHunt, Netlas, Chaos, BinaryEdge, ...) are already queried by subfinder --
# the binding constraint is API keys, not tooling. Drop a commented template so
# the operator knows exactly where to paste keys. Never overwrite an existing one.
# ===========================================================================
scaffold_subfinder_config(){
  local cfgdir cfg
  cfgdir="${HOME:-/root}/.config/subfinder"; cfg="$cfgdir/provider-config.yaml"
  [ -f "$cfg" ] && { ok "subfinder provider-config present ($cfg)"; return 0; }
  mkdir -p "$cfgdir" 2>/dev/null || { warn "could not create $cfgdir; skipping provider-config scaffold"; return 0; }
  cat > "$cfg" <<'YAML'
# subfinder provider-config -- paste API keys to unlock premium passive sources.
# Docs: https://docs.projectdiscovery.io/tools/subfinder/install#post-installation
# Format is provider: [ "key" ] (some take "id:secret"). Remove the leading '#'
# and fill in keys you have. Free tiers exist for many of these.
#
#virustotal: [ "YOUR_VT_API_KEY" ]                 # passive DNS + subdomains (free tier)
#securitytrails: [ "YOUR_KEY" ]                     # DNS history / subdomains
#censys: [ "API_ID:API_SECRET" ]                    # cert + host dataset
#shodan: [ "YOUR_KEY" ]                             # host/service data
#fullhunt: [ "YOUR_KEY" ]                           # attack-surface dataset
#netlas: [ "YOUR_KEY" ]                             # internet scan dataset
#chaos: [ "YOUR_KEY" ]                              # ProjectDiscovery public bug-bounty subdomains
#binaryedge: [ "YOUR_KEY" ]
#bevigil: [ "YOUR_KEY" ]
#builtwith: [ "YOUR_KEY" ]
#certspotter: [ "YOUR_KEY" ]
#github: [ "YOUR_GITHUB_PAT" ]                      # also used by run-recon --github
#leakix: [ "YOUR_KEY" ]
YAML
  ok "wrote subfinder provider-config scaffold: $cfg (add API keys to unlock premium sources)"
}
scaffold_subfinder_config

# ===========================================================================
# 6) optional heavy assets
# ===========================================================================
if [ "$INCLUDE_HEAVY" = "1" ]; then
  log "Heavy mode: SecLists + nuclei-templates + feroxbuster"
  if [ ! -d "$INSTALL_ROOT/wordlists/SecLists/.git" ]; then
    as_root git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
      "$INSTALL_ROOT/wordlists/SecLists" >/dev/null 2>&1 \
      && ok "SecLists cloned" || warn "SecLists clone failed"
  else
    ok "SecLists present"
  fi
  # Run as the invoking user so templates land in that user's home, not root's.
  if have nuclei; then
    nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated" \
      || warn "nuclei template update failed"
  fi
  if ! have feroxbuster; then
    log "Installing feroxbuster..."
    _fx="$(mktemp -d)"
    if curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh -o "$_fx/install-nix.sh"; then
      ( cd "$_fx" && bash install-nix.sh >/dev/null 2>&1 )
      if [ -f "$_fx/feroxbuster" ]; then
        as_root install -m 0755 "$_fx/feroxbuster" /usr/local/bin/feroxbuster \
          && ok "feroxbuster installed" || warn "feroxbuster install failed"
      else
        warn "feroxbuster binary not produced by installer"
      fi
    else
      warn "feroxbuster installer download failed"
    fi
    rm -rf "$_fx"
  fi
else
  log "Skipping heavy assets (--include-heavy enables SecLists / nuclei-templates / feroxbuster)."
fi

# ===========================================================================
# 7) env files + marker
# ===========================================================================
as_root tee "$INSTALL_ROOT/recon.env" >/dev/null <<ENV
# Source this for an interactive recon shell.
export RECON_ROOT="$INSTALL_ROOT"
export PATH="/usr/local/go/bin:/usr/local/bin:\$PATH"
export GOPATH="$INSTALL_ROOT/go"
export SECLISTS="$INSTALL_ROOT/wordlists/SecLists"
ENV

as_root tee /etc/profile.d/recon.sh >/dev/null <<'PROF'
export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"
PROF
as_root chmod 0644 /etc/profile.d/recon.sh

date | as_root tee "$INSTALL_ROOT/.provisioned" >/dev/null

# ===========================================================================
# 8) install the companion operational scripts
#    outcrop.sh needs generate-report.sh, recon-db.sh and ship-recon.sh to live NEXT
#    TO IT (it resolves them relative to its own path), so install them together.
#    run-recon.sh (the former name, a wrapper that runs outcrop.sh) goes beside them.
# ===========================================================================
if [ "$RUNNER_FOUND" = "yes" ]; then
  log "Installing toolkit scripts from $SCRIPT_DIR ..."
  as_root install -d "$INSTALL_ROOT/bin" 2>/dev/null || true
  if as_root install -m 0755 "$SCRIPT_DIR/outcrop.sh" "$INSTALL_ROOT/bin/outcrop.sh" \
     && as_root ln -sf "$INSTALL_ROOT/bin/outcrop.sh" /usr/local/bin/outcrop; then
    ok "Installed: $INSTALL_ROOT/bin/outcrop.sh  (command: outcrop)"
  else
    warn "Could not install outcrop.sh automatically."
  fi
  # the former name: existing scripts and cron jobs that call run-recon keep working
  if [ -f "$SCRIPT_DIR/run-recon.sh" ] && as_root install -m 0755 "$SCRIPT_DIR/run-recon.sh" "$INSTALL_ROOT/bin/run-recon.sh" \
     && as_root ln -sf "$INSTALL_ROOT/bin/run-recon.sh" /usr/local/bin/run-recon; then
    ok "Installed: $INSTALL_ROOT/bin/run-recon.sh  (command: run-recon, the former name; it runs outcrop)"
  fi
  for _companion in generate-report.sh recon-db.sh ship-recon.sh; do
    _cmd="${_companion%.sh}"
    if [ -f "$SCRIPT_DIR/$_companion" ]; then
      if as_root install -m 0755 "$SCRIPT_DIR/$_companion" "$INSTALL_ROOT/bin/$_companion" \
         && as_root ln -sf "$INSTALL_ROOT/bin/$_companion" "/usr/local/bin/$_cmd"; then
        ok "Installed: $INSTALL_ROOT/bin/$_companion  (command: $_cmd)"
      else
        warn "Could not install $_companion automatically."
      fi
    else
      warn "$_companion not found next to this installer; the ${_cmd} feature will be unavailable from the installed command."
    fi
  done
  # data the vulns join reads next to recon-db.sh: the CPE alias groups (1.20)
  if [ -f "$SCRIPT_DIR/cpe-aliases.json" ]; then
    if as_root install -m 0644 "$SCRIPT_DIR/cpe-aliases.json" "$INSTALL_ROOT/bin/cpe-aliases.json"; then
      ok "Installed: $INSTALL_ROOT/bin/cpe-aliases.json  (CPE alias groups for recon-db vulns)"
    else
      warn "Could not install cpe-aliases.json; recon-db vulns will join exact CPE names only."
    fi
  fi
  # the JSON Schemas of --json's records and of the Tideline envelope (1.20), for consumers
  if [ -d "$SCRIPT_DIR/schemas" ]; then
    if as_root install -d -m 0755 "$INSTALL_ROOT/bin/schemas" \
       && as_root install -m 0644 "$SCRIPT_DIR"/schemas/*.json "$SCRIPT_DIR"/schemas/SHA256SUMS "$INSTALL_ROOT/bin/schemas/"; then
      ok "Installed: $INSTALL_ROOT/bin/schemas/  (JSON Schemas of the --json records and the Tideline envelope)"
    else
      warn "Could not install schemas/."
    fi
  fi
else
  warn "outcrop.sh not found next to this script ($SCRIPT_DIR)."
  warn "Place outcrop.sh (with generate-report.sh, recon-db.sh, ship-recon.sh and run-recon.sh) alongside this installer and re-run."
fi

# ===========================================================================
# 8b) recon PostgreSQL cache database (reuse the local msf/postgres service)
# ===========================================================================
if [ "$SETUP_DB" = "1" ]; then
  log "Configuring the recon PostgreSQL cache database (reuses the local msf/postgres service)..."
  DB_LIB="$SCRIPT_DIR/recon-db.sh"
  [ -f "$DB_LIB" ] || DB_LIB="$INSTALL_ROOT/bin/recon-db.sh"
  if [ ! -f "$DB_LIB" ]; then
    warn "recon-db.sh not found; skipping DB setup ('--db' will run uncached until you run 'recon-db init')."
  elif [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would ensure a postgres server, then run: recon-db.sh init (PRIMARY: provision a dedicated password-authed 'recon' role + DB on the local PostgreSQL, msfdb-style; BACKUP: reuse msfdb credentials)."
  else
    # ensure a postgres SERVER exists to host the recon DB. On Kali the msf
    # service is already present, so this installs nothing; on a bare box we
    # add the server package best-effort.
    if ! ls /usr/lib/postgresql/*/bin/postgres >/dev/null 2>&1 \
       && ! have postgres && ! have pg_ctl && ! have pg_ctlcluster; then
      log "No local PostgreSQL server detected; installing one (best-effort)..."
      case "$PKG_MGR" in
        apt)    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql \
                  || warn "postgresql server install failed; set one up manually, then run 'recon-db init'." ;;
        dnf)    as_root dnf install -y postgresql-server \
                  && as_root postgresql-setup --initdb 2>/dev/null \
                  || warn "postgresql-server needs manual initdb; then run 'recon-db init'." ;;
        pacman) as_root pacman -S --noconfirm postgresql \
                  || warn "postgresql install failed; initdb + start manually, then run 'recon-db init'." ;;
        *)      warn "Unknown package manager; install a PostgreSQL server, then run 'recon-db init'." ;;
      esac
    fi
    # run init as the invoking (non-root) user so the role + ~/.config/recon/db.env
    # land in the right home; recon-db.sh sudo-escalates internally for the
    # superuser bits (CREATE ROLE / CREATE DATABASE / service start).
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
      sudo -u "$SUDO_USER" -H bash "$DB_LIB" init && DB_OK=1 || DB_OK=0
    else
      bash "$DB_LIB" init && DB_OK=1 || DB_OK=0
    fi
    if [ "${DB_OK:-0}" = "1" ]; then
      ok "recon DB ready - outcrop --db will cache crawl/OSINT results and persist inventory."
    else
      warn "recon DB setup did not complete; '--db' will run uncached. See recon-db.sh notes to finish manually."
    fi
  fi
else
  log "Skipping recon DB setup (--no-db); '--db' at runtime will run uncached unless you run 'recon-db init' later."
fi

# ===========================================================================
# 8c) optional local caching DNS resolver (unbound) -- cuts DNS-stage timeouts
# ===========================================================================
if [ "$SETUP_DNS_CACHE" = "1" ]; then
  log "Setting up a local caching DNS resolver (unbound)..."
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would install unbound + write a 127.0.0.1 caching config + a resolvers file."
  else
    case "$PKG_MGR" in
      apt)    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unbound || warn "unbound install failed";;
      dnf)    as_root dnf install -y unbound || warn "unbound install failed";;
      pacman) as_root pacman -S --noconfirm unbound || warn "unbound install failed";;
      *)      warn "Unknown package manager; install unbound manually.";;
    esac
    if have unbound || [ -d /etc/unbound ]; then
      as_root mkdir -p /etc/unbound/unbound.conf.d 2>/dev/null || true
      if as_root tee /etc/unbound/unbound.conf.d/recon-cache.conf >/dev/null <<'UCONF'
server:
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    prefetch: yes
    cache-max-ttl: 86400
    num-threads: 2
    msg-cache-size: 64m
    rrset-cache-size: 128m
forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 8.8.8.8
UCONF
      then
        as_root systemctl enable --now unbound 2>/dev/null || as_root service unbound restart 2>/dev/null || true
        as_root install -d "$INSTALL_ROOT" 2>/dev/null || true
        printf '127.0.0.1\n' | as_root tee "$INSTALL_ROOT/resolvers.txt" >/dev/null 2>&1 || true
        ok "unbound caching resolver ready. Point DNS-heavy stages at it with:"
        ok "    outcrop --resolvers $INSTALL_ROOT/resolvers.txt ..."
      else
        warn "Could not write the unbound config; skipping DNS cache."
      fi
    else
      warn "unbound not available after install; skipping DNS cache setup."
    fi
  fi
fi

# ===========================================================================
# 9) verification
# ===========================================================================
log "Verifying installed tools..."
PRESENT=""; MISSING=""
for tool in gau waybackurls anew unfurl qsreplace gf httpx-toolkit katana subfinder dnsx \
            tlsx alterx nuclei hakrawler gospider ffuf subjs getJS urlfinder waymore \
            arjun uro dirsearch xnLinkFinder linkfinder secretfinder \
            naabu shuffledns puredns massdns asnmap mapcidr cdncheck uncover notify cloudlist tldfinder vulnx \
            amass assetfinder findomain subzy gowitness jsluice trufflehog \
            github-subdomains github-endpoints cloud_enum dnsvalidator \
            wpscan droopescan joomscan cmseek whatweb tookie-osint \
            psql unbound python3 go; do
  if have "$tool"; then PRESENT="$PRESENT $tool"; else MISSING="$MISSING $tool"; fi
done
echo >&2
ok "PRESENT:$PRESENT"
if [ -n "$MISSING" ]; then warn "MISSING:$MISSING"; else ok "All expected tools present."; fi
echo >&2
ok "Provisioning complete. Toolkit root: $INSTALL_ROOT"

# ===========================================================================
# 10) next steps
# ===========================================================================
echo >&2
ok "================================================================"
ok " Setup complete."
{
  echo ""
  echo "Next steps:"
  echo ""
  echo "  # open a fresh shell (or: source $INSTALL_ROOT/recon.env)"
  echo "  # create your scope file (one domain per line)"
  echo "  printf '%s\\n' example.com api.example.com > domains.txt"
  echo ""
  echo "  # run the enumeration (passive + crawl + validate by default)"
  echo "  outcrop -i domains.txt -o results.csv          # (run-recon, the former name, still works)"
  echo ""
  echo "  # faster / quieter variants:"
  echo "  outcrop -i domains.txt --passive-only          # no traffic to targets"
  echo "  outcrop -i domains.txt --subs --deep -t 10     # subdomains + waymore, 10 parallel"
  echo "  outcrop -i domains.txt --subs --resolve --certs --permute"
  echo "                                                 # validated hosts + cert SANs + permutations"
  echo "                                                 # (dnsx/tlsx/httpx routed via dedicated resolvers)"
  echo ""
  echo "  # every run also writes an HTML report next to the CSV:"
  echo "  #   results.csv.report.html   (findings + screenshots + per-host detail; --no-report to skip)"
  echo ""
  if [ "$SETUP_DB" = "1" ]; then
    echo "  # the recon PostgreSQL cache is set up -- enable it to skip re-crawling"
    echo "  # targets and re-hitting OSINT APIs, and to persist each run's inventory:"
    echo "  outcrop -i domains.txt -o results.csv --osint --db"
    echo "  recon-db stats                                 # inspect the cache/store"
  else
    echo "  # recon DB was skipped (--no-db). To enable caching later:"
    echo "  sudo recon-db init  &&  outcrop -i domains.txt --db"
  fi
  echo ""
  if [ "$WSL" = "yes" ]; then
    echo "  # you're inside WSL: open the CSV from Windows via"
    echo "  #   \\\\wsl.localhost\\<distro>\\home\\$USER\\results.csv   (or write under /mnt/c/...)"
    echo ""
  fi
  echo "Re-run this installer any time (idempotent). Use --force to upgrade tools,"
  echo "--include-heavy to add SecLists + nuclei-templates + feroxbuster."
} >&2
ok "================================================================"

exit 0
