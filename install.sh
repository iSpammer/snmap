#!/bin/bash
# SmartNmap v3.0 - Installation Script
# Usage:
#   ./install.sh          # Check what's missing, print install hints
#   ./install.sh --run    # Auto-install everything possible

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'
BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "  ${CYAN}[*]${RESET} $1"; }
good()  { echo -e "  ${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${RESET} $1"; }
error() { echo -e "  ${RED}[-]${RESET} $1"; }

AUTO_INSTALL=false
[[ "$1" == "--run" ]] && AUTO_INSTALL=true

echo -e "${CYAN}${BOLD}"
echo "  SmartNmap v3.0 - Installer"
echo "  =========================="
$AUTO_INSTALL && echo "  Mode: AUTO-INSTALL (--run)" || echo "  Mode: CHECK only  (re-run with --run to auto-install)"
echo -e "${RESET}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SMARTNMAP="$SCRIPT_DIR/smartnmap.py"

# ── Privilege helper ──
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
        info "Not root — will use sudo for privileged commands"
    else
        warn "Not root and no sudo found — some installs may fail"
    fi
fi

run_cmd() {
    # run_cmd <desc> <cmd...>
    local desc="$1"; shift
    info "Installing $desc..."
    if "$@" 2>/dev/null; then
        good "$desc: installed"
        return 0
    else
        warn "$desc: install failed — try manually: $*"
        return 1
    fi
}

apt_install() {
    # Non-interactive apt install
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -q "$@" 2>/dev/null
}

# ── Detect NSE scripts directory ──
NSE_DIR=""
for dir in /usr/share/nmap/scripts /snap/nmap/current/usr/share/nmap/scripts /usr/local/share/nmap/scripts; do
    [ -d "$dir" ] && NSE_DIR="$dir" && break
done

if [ -z "$NSE_DIR" ]; then
    error "Could not find nmap NSE scripts directory"
    if $AUTO_INSTALL; then
        run_cmd "nmap" $SUDO apt_install nmap
        NSE_DIR="/usr/share/nmap/scripts"
    else
        info "Install nmap first: apt install nmap"
        exit 1
    fi
fi

info "NSE scripts directory: $NSE_DIR"
info "SmartNmap location: $SMARTNMAP"

# ── Make executable & symlink ──
chmod +x "$SMARTNMAP"
good "Made smartnmap.py executable"

SYMLINK_DIR=""
[ -w /usr/local/bin ] && SYMLINK_DIR="/usr/local/bin"
[ -z "$SYMLINK_DIR" ] && command -v sudo &>/dev/null && SYMLINK_DIR="/usr/local/bin"
[ -z "$SYMLINK_DIR" ] && SYMLINK_DIR="$HOME/.local/bin"

mkdir -p "$SYMLINK_DIR"
ln -sf "$SMARTNMAP" "$SYMLINK_DIR/smartnmap" 2>/dev/null && \
    good "Created symlink: $SYMLINK_DIR/smartnmap" || \
    warn "Could not create symlink (run with sudo or add $SCRIPT_DIR to PATH)"

# ── NSE Scripts ──
echo ""
echo -e "${BOLD}Installing NSE Scripts...${RESET}"

CAN_WRITE=false
[ -w "$NSE_DIR" ] && CAN_WRITE=true
if ! $CAN_WRITE && $AUTO_INSTALL; then
    $SUDO chmod o+w "$NSE_DIR" 2>/dev/null && CAN_WRITE=true
fi

install_nse_file() {
    local name="$1" url="$2" dest="$NSE_DIR/$name"
    if [ -f "$dest" ]; then good "$name: already installed"; return; fi
    if $CAN_WRITE; then
        curl -sL -o "$dest" "$url" 2>/dev/null && good "Installed $name" || warn "Failed: curl -sL -o $dest $url"
    else
        warn "$name: skipped (no write access to $NSE_DIR — re-run as root)"
    fi
}

install_nse_repo() {
    local name="$1" url="$2" dest="$NSE_DIR/$3" check="$4"
    if [ -f "$check" ] || [ -d "$dest" ]; then good "$name: already installed"; return; fi
    if $CAN_WRITE; then
        git clone --depth 1 "$url" "$dest" 2>/dev/null && good "Installed $name" || warn "Failed to clone $name"
    else
        warn "$name: skipped (no write access — re-run as root)"
    fi
}

install_nse_file "vulners.nse" \
    "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"
install_nse_file "freevulnsearch.nse" \
    "https://raw.githubusercontent.com/OCSAF/freevulnsearch/master/freevulnsearch.nse"
install_nse_file "log4shell.nse" \
    "https://raw.githubusercontent.com/giterlizzi/nmap-log4shell/main/log4shell.nse"
install_nse_file "http-spring4shell.nse" \
    "https://raw.githubusercontent.com/gpiechnik2/nmap-spring4shell/main/http-spring4shell.nse"
install_nse_repo "scipag/vulscan" \
    "https://github.com/scipag/vulscan.git" "vulscan" "$NSE_DIR/vulscan/vulscan.nse"
install_nse_repo "nccgroup/nmap-nse-vulnerability-scripts" \
    "https://github.com/nccgroup/nmap-nse-vulnerability-scripts.git" "nccgroup-vuln" "$NSE_DIR/nccgroup-vuln"
install_nse_repo "cldrn/nmap-nse-scripts" \
    "https://github.com/cldrn/nmap-nse-scripts.git" "cldrn-nse" "$NSE_DIR/cldrn-nse"

if $CAN_WRITE; then
    info "Updating nmap script database..."
    nmap --script-updatedb 2>/dev/null && good "Script database updated" || warn "Could not update script db"
fi

# ── Tool checker / installer ──
echo ""
echo -e "${BOLD}Checking system tools...${RESET}"

# check_tool <binary> <description> <apt-pkg> <pip-pkg> <gem-pkg> <go-pkg> <manual>
# Pass "-" to skip a method
check_tool() {
    local bin="$1" desc="$2" apt_pkg="$3" pip_pkg="$4" gem_pkg="$5" go_pkg="$6" manual="$7"
    if command -v "$bin" &>/dev/null; then
        good "$bin: installed"
        return 0
    fi
    warn "$bin: NOT installed"
    if ! $AUTO_INSTALL; then
        [ "$apt_pkg" != "-" ] && info "  apt install $apt_pkg"
        [ "$pip_pkg"  != "-" ] && info "  pip3 install $pip_pkg"
        [ "$gem_pkg"  != "-" ] && info "  gem install $gem_pkg"
        [ "$go_pkg"   != "-" ] && info "  go install $go_pkg"
        [ "$manual"   != "-" ] && info "  $manual"
        return 1
    fi
    # Auto-install: try methods in order
    if [ "$apt_pkg" != "-" ]; then
        info "  → apt install $apt_pkg"
        apt_install "$apt_pkg" && good "$bin: installed via apt" && return 0
    fi
    if [ "$pip_pkg" != "-" ]; then
        info "  → pip3 install $pip_pkg"
        pip3 install --break-system-packages "$pip_pkg" 2>/dev/null || \
        pip3 install "$pip_pkg" 2>/dev/null && good "$bin: installed via pip3" && return 0
    fi
    if [ "$gem_pkg" != "-" ]; then
        info "  → gem install $gem_pkg"
        gem install "$gem_pkg" 2>/dev/null && good "$bin: installed via gem" && return 0
    fi
    if [ "$go_pkg" != "-" ] && command -v go &>/dev/null; then
        info "  → go install $go_pkg"
        go install "$go_pkg" 2>/dev/null && good "$bin: installed via go" && return 0
    fi
    [ "$manual" != "-" ] && warn "  Could not auto-install $bin — try: $manual"
    return 1
}

echo -e "\n${BOLD}Core:${RESET}"
check_tool nmap         "Nmap"          "nmap"          "-"       "-" "-" "-"
check_tool curl         "curl"          "curl"          "-"       "-" "-" "-"
check_tool searchsploit "searchsploit"  "exploitdb"     "-"       "-" "-" "-"
check_tool git          "git"           "git"           "-"       "-" "-" "-"

echo -e "\n${BOLD}Port discovery boosters:${RESET}"
check_tool rustscan     "rustscan"      "rustscan"      "-"       "-" "-" "cargo install rustscan"
check_tool masscan      "masscan"       "masscan"       "-"       "-" "-" "-"

echo -e "\n${BOLD}Web enumeration:${RESET}"
check_tool nikto        "nikto"         "nikto"         "-"       "-" "-" "-"
check_tool gobuster     "gobuster"      "gobuster"      "-"       "-" "-" "-"
check_tool ffuf         "ffuf"          "ffuf"          "-"       "-" "github.com/ffuf/ffuf/v2@latest" "-"
check_tool whatweb      "whatweb"       "whatweb"       "-"       "-" "-" "-"
check_tool wpscan       "wpscan"        "-"             "-"       "wpscan" "-" "-"
check_tool nuclei       "nuclei"        "-"             "-"       "-" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "-"

echo -e "\n${BOLD}SSL/TLS:${RESET}"
check_tool sslscan      "sslscan"       "sslscan"       "-"       "-" "-" "-"
check_tool openssl      "openssl"       "openssl"       "-"       "-" "-" "-"

echo -e "\n${BOLD}SMB / Windows:${RESET}"
check_tool enum4linux    "enum4linux"   "enum4linux"    "-"       "-" "-" "-"
check_tool enum4linux-ng "enum4linux-ng" "-"            "enum4linux-ng" "-" "-" "-"
check_tool smbclient    "smbclient"     "smbclient"     "-"       "-" "-" "-"
check_tool smbmap       "smbmap"        "-"             "smbmap"  "-" "-" "-"
check_tool netexec      "netexec"       "-"             "netexec" "-" "-" "-"
check_tool crackmapexec "crackmapexec"  "-"             "crackmapexec" "-" "-" "-"
check_tool rpcclient    "rpcclient"     "samba-common-bin" "-"    "-" "-" "-"

echo -e "\n${BOLD}NFS / RPC / LDAP / SNMP:${RESET}"
check_tool showmount    "showmount"     "nfs-common"    "-"       "-" "-" "-"
check_tool rpcinfo      "rpcinfo"       "rpcbind"       "-"       "-" "-" "-"
check_tool ldapsearch   "ldapsearch"    "ldap-utils"    "-"       "-" "-" "-"
check_tool snmpwalk     "snmpwalk"      "snmp"          "-"       "-" "-" "-"
check_tool onesixtyone  "onesixtyone"   "onesixtyone"   "-"       "-" "-" "-"

echo -e "\n${BOLD}Brute forcing:${RESET}"
check_tool hydra        "hydra"         "hydra"         "-"       "-" "-" "-"
check_tool medusa       "medusa"        "medusa"        "-"       "-" "-" "-"

echo -e "\n${BOLD}Web crawlers / URL & param discovery:${RESET}"
check_tool katana       "katana"        "-" "-" "-" "github.com/projectdiscovery/katana/cmd/katana@latest" "-"
check_tool hakrawler    "hakrawler"     "-" "-" "-" "github.com/hakluke/hakrawler@latest" "-"
check_tool gospider     "gospider"      "-" "-" "-" "github.com/jaeles-project/gospider@latest" "-"
check_tool gau          "gau"           "-" "-" "-" "github.com/lc/gau/v2/cmd/gau@latest" "-"
check_tool waybackurls  "waybackurls"   "-" "-" "-" "github.com/tomnomnom/waybackurls@latest" "-"
check_tool arjun        "arjun"         "-" "arjun" "-" "-" "-"
check_tool httpx        "httpx"         "-" "-" "-" "github.com/projectdiscovery/httpx/cmd/httpx@latest" "-"
check_tool subfinder    "subfinder"     "-" "-" "-" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "-"
check_tool feroxbuster  "feroxbuster"   "feroxbuster" "-" "-" "-" "cargo install feroxbuster"

echo -e "\n${BOLD}Injection / SSRF (active-gated — used only with --active or --ctf):${RESET}"
check_tool sqlmap       "sqlmap"        "sqlmap"        "sqlmap" "-" "-" "-"
check_tool dalfox       "dalfox"        "-" "-" "-" "github.com/hahwul/dalfox/v2@latest" "-"
check_tool commix       "commix"        "commix"        "-" "-" "-" "-"
check_tool interactsh-client "interactsh-client" "-" "-" "-" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "-"
# SSRFmap has no package — clone it and symlink a launcher onto PATH
if ! command -v ssrfmap &>/dev/null; then
    warn "ssrfmap: NOT installed"
    if $AUTO_INSTALL; then
        SSRFMAP_DIR="$HOME/.local/share/SSRFmap"
        if git clone --depth 1 https://github.com/swisskyrepo/SSRFmap "$SSRFMAP_DIR" 2>/dev/null; then
            pip3 install --break-system-packages -r "$SSRFMAP_DIR/requirements.txt" 2>/dev/null
            printf '#!/bin/bash\ncd "%s" && python3 ssrfmap.py "$@"\n' "$SSRFMAP_DIR" \
                > "$HOME/.local/bin/ssrfmap" 2>/dev/null && chmod +x "$HOME/.local/bin/ssrfmap" \
                && good "ssrfmap: installed to ~/.local/bin (ensure it is on PATH)" \
                || warn "ssrfmap: cloned to $SSRFMAP_DIR — add a launcher to PATH manually"
        else
            warn "ssrfmap: clone failed — git clone https://github.com/swisskyrepo/SSRFmap"
        fi
    else
        info "  git clone https://github.com/swisskyrepo/SSRFmap  (then symlink ssrfmap.py onto PATH)"
    fi
fi

echo -e "\n${BOLD}Active Directory / Kerberos:${RESET}"
check_tool kerbrute        "kerbrute"          "-" "-" "-" "github.com/ropnop/kerbrute@latest" "-"
check_tool GetUserSPNs.py  "impacket (Kerberoast/AS-REP/lookupsid)" "-" "impacket" "-" "-" "pipx install impacket"
check_tool bloodhound-python "bloodhound-python" "-" "bloodhound" "-" "-" "-"
check_tool evil-winrm      "evil-winrm"        "-" "-" "evil-winrm" "-" "-"

# ── Node.js / Puter AI ──
echo -e "\n${BOLD}AI (Puter/GPT — free, no key needed):${RESET}"

NODE_OK=false
NODE_VER=""
if command -v node &>/dev/null; then
    NODE_VER=$(node --version 2>/dev/null)
    NODE_MAJOR=$(node -e 'process.stdout.write(String(parseInt(process.versions.node)))' 2>/dev/null)
    if [ "${NODE_MAJOR:-0}" -ge 18 ] 2>/dev/null; then
        good "node $NODE_VER (>=18 ✓)"
        NODE_OK=true
    else
        warn "node $NODE_VER is too old (need >=18)"
        NODE_OK=false
    fi
else
    warn "node: not installed"
fi

if ! $NODE_OK; then
    if $AUTO_INSTALL; then
        info "Installing Node.js 18 via NodeSource..."
        curl -fsSL https://deb.nodesource.com/setup_18.x 2>/dev/null | $SUDO bash - 2>/dev/null && \
        apt_install nodejs && NODE_OK=true && good "node: installed ($(node --version))" || \
        warn "Could not auto-install Node 18 — install manually: https://nodejs.org"
    else
        info "  Install Node >=18: curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash - && sudo apt install nodejs"
    fi
fi

if $NODE_OK; then
    if node -e 'require("@heyputer/puter.js")' 2>/dev/null; then
        good "@heyputer/puter.js: installed"
    else
        warn "@heyputer/puter.js: not installed"
        if $AUTO_INSTALL || true; then
            info "  Installing: npm install -g @heyputer/puter.js"
            npm install -g @heyputer/puter.js 2>/dev/null && \
                good "@heyputer/puter.js: installed" || \
                warn "npm install failed — try: npm install -g @heyputer/puter.js"
        fi
    fi
fi

# ── Wordlists ──
echo -e "\n${BOLD}Wordlists:${RESET}"
for wl in /usr/share/wordlists /usr/share/seclists; do
    if [ -d "$wl" ]; then
        good "$wl: present"
    else
        warn "$wl: missing"
        if $AUTO_INSTALL && [ "$wl" = "/usr/share/seclists" ]; then
            info "  Cloning SecLists (~500MB)..."
            git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null && \
                good "SecLists: installed" || warn "SecLists clone failed"
        else
            info "  Get SecLists: git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists"
        fi
    fi
done

# ── Done ──
echo ""
echo -e "${GREEN}${BOLD}Done!${RESET}"
echo ""
echo -e "  ${BOLD}Usage:${RESET}"
echo -e "    ${CYAN}smartnmap <target>${RESET}                   # Quick scan"
echo -e "    ${CYAN}smartnmap <target> --full${RESET}            # All 65k TCP ports"
echo -e "    ${CYAN}smartnmap <target> --ctf -ai${RESET}         # CTF mode + AI"
echo -e "    ${CYAN}smartnmap <target> --bb -ai${RESET}           # Bug bounty + AI"
echo -e "    ${CYAN}smartnmap <target> --vhosts${RESET}           # + vhost brute-force"
echo -e "    ${CYAN}smartnmap <target>/24${RESET}                # CIDR sweep"
echo -e "    ${CYAN}smartnmap --install-scripts${RESET}          # Update NSE scripts"
echo ""
echo -e "  ${BOLD}AI config:${RESET}"
echo -e "    Gemini key: ${CYAN}export GEMINI_API_KEY=your-key${RESET}"
echo -e "    Or:         ${CYAN}echo '{\"gemini_api_key\":\"...\"}' > ~/.config/smartnmap/config.json${RESET}"
echo -e "    Free GPT:   ${CYAN}npm install -g @heyputer/puter.js${RESET}  (no key needed)"
echo ""
echo -e "  Or run directly: ${CYAN}python3 $SMARTNMAP <target>${RESET}"
echo ""
