#!/bin/bash
# SmartNmap v3.0 - Installation Script
# Installs NSE scripts, tools, and sets up the smartnmap command

set -e

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'
BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "  ${CYAN}[*]${RESET} $1"; }
good()  { echo -e "  ${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${RESET} $1"; }
error() { echo -e "  ${RED}[-]${RESET} $1"; }

echo -e "${CYAN}${BOLD}"
echo "  SmartNmap v3.0 - Installer"
echo "  =========================="
echo -e "${RESET}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SMARTNMAP="$SCRIPT_DIR/smartnmap.py"

# Detect NSE scripts directory
NSE_DIR=""
for dir in /usr/share/nmap/scripts /snap/nmap/current/usr/share/nmap/scripts /usr/local/share/nmap/scripts; do
    if [ -d "$dir" ]; then
        NSE_DIR="$dir"
        break
    fi
done

if [ -z "$NSE_DIR" ]; then
    error "Could not find nmap NSE scripts directory"
    info "Install nmap first: apt install nmap"
    exit 1
fi

info "NSE scripts directory: $NSE_DIR"
info "SmartNmap location: $SMARTNMAP"

# ── Make executable ──
chmod +x "$SMARTNMAP"
good "Made smartnmap.py executable"

# ── Create symlink ──
if [ -w /usr/local/bin ]; then
    ln -sf "$SMARTNMAP" /usr/local/bin/smartnmap
    good "Created symlink: /usr/local/bin/smartnmap"
elif [ -w "$HOME/.local/bin" ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$SMARTNMAP" "$HOME/.local/bin/smartnmap"
    good "Created symlink: $HOME/.local/bin/smartnmap"
else
    warn "Cannot create symlink - run with: python3 $SMARTNMAP"
fi

# ── Install NSE Scripts ──
echo ""
echo -e "${BOLD}Installing NSE Scripts...${RESET}"

# Check if we can write to NSE dir
CAN_WRITE=false
if [ -w "$NSE_DIR" ]; then
    CAN_WRITE=true
fi

install_nse_file() {
    local name="$1"
    local url="$2"
    local dest="$NSE_DIR/$name"

    if [ -f "$dest" ]; then
        good "$name: already installed"
        return
    fi

    if [ "$CAN_WRITE" = true ]; then
        info "Downloading $name..."
        if curl -sL -o "$dest" "$url" 2>/dev/null; then
            good "Installed $name"
        else
            warn "Failed to download $name"
            info "  Manual: curl -sL -o $dest $url"
        fi
    else
        warn "$name: not installed (no write access to $NSE_DIR)"
        info "  Run as root: curl -sL -o $dest $url"
    fi
}

install_nse_repo() {
    local name="$1"
    local url="$2"
    local dest="$NSE_DIR/$3"
    local check="$4"

    if [ -f "$check" ] || [ -d "$dest" ]; then
        good "$name: already installed"
        return
    fi

    if [ "$CAN_WRITE" = true ]; then
        info "Cloning $name..."
        if git clone --depth 1 "$url" "$dest" 2>/dev/null; then
            good "Installed $name"
        else
            warn "Failed to clone $name"
            info "  Manual: git clone $url $dest"
        fi
    else
        warn "$name: not installed (no write access)"
        info "  Run as root: git clone $url $dest"
    fi
}

# Single NSE files
install_nse_file "vulners.nse" \
    "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"

install_nse_file "freevulnsearch.nse" \
    "https://raw.githubusercontent.com/OCSAF/freevulnsearch/master/freevulnsearch.nse"

install_nse_file "log4shell.nse" \
    "https://raw.githubusercontent.com/giterlizzi/nmap-log4shell/main/log4shell.nse"

install_nse_file "http-spring4shell.nse" \
    "https://raw.githubusercontent.com/gpiechnik2/nmap-spring4shell/main/http-spring4shell.nse"

# Git repos
install_nse_repo "scipag/vulscan" \
    "https://github.com/scipag/vulscan.git" \
    "vulscan" \
    "$NSE_DIR/vulscan/vulscan.nse"

install_nse_repo "nccgroup/nmap-nse-vulnerability-scripts" \
    "https://github.com/nccgroup/nmap-nse-vulnerability-scripts.git" \
    "nccgroup-vuln" \
    "$NSE_DIR/nccgroup-vuln"

install_nse_repo "cldrn/nmap-nse-scripts" \
    "https://github.com/cldrn/nmap-nse-scripts.git" \
    "cldrn-nse" \
    "$NSE_DIR/cldrn-nse"

# Update script database
if [ "$CAN_WRITE" = true ]; then
    info "Updating nmap script database..."
    nmap --script-updatedb 2>/dev/null && good "Script database updated" || warn "Could not update script db"
fi

# ── Install System Tools ──
echo ""
echo -e "${BOLD}Checking system tools...${RESET}"

check_tool() {
    local tool="$1"
    local install_cmd="$2"
    if command -v "$tool" &>/dev/null; then
        good "$tool: installed"
    else
        warn "$tool: NOT installed"
        info "  Install: $install_cmd"
    fi
}

echo -e "${BOLD}Core tools:${RESET}"
check_tool nmap          "apt install nmap"
check_tool curl          "apt install curl"
check_tool searchsploit  "apt install exploitdb"

echo ""
echo -e "${BOLD}Port discovery boosters:${RESET}"
check_tool rustscan      "cargo install rustscan  OR  apt install rustscan"
check_tool masscan       "apt install masscan"

echo ""
echo -e "${BOLD}Web enumeration:${RESET}"
check_tool nikto         "apt install nikto"
check_tool gobuster      "apt install gobuster"
check_tool ffuf          "apt install ffuf  OR  go install github.com/ffuf/ffuf/v2@latest"
check_tool whatweb       "apt install whatweb"
check_tool wpscan        "gem install wpscan"
check_tool nuclei        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

echo ""
echo -e "${BOLD}SSL/TLS analysis:${RESET}"
check_tool sslscan       "apt install sslscan"
check_tool testssl.sh    "git clone https://github.com/drwetter/testssl.sh"
check_tool openssl       "apt install openssl"

echo ""
echo -e "${BOLD}SMB / Windows:${RESET}"
check_tool enum4linux    "apt install enum4linux"
check_tool enum4linux-ng "pip3 install enum4linux-ng"
check_tool smbclient     "apt install smbclient"
check_tool smbmap        "pip3 install smbmap"
check_tool netexec       "pip3 install netexec (supersedes crackmapexec)"
check_tool crackmapexec  "pip3 install crackmapexec"
check_tool rpcclient     "apt install samba-common-bin"

echo ""
echo -e "${BOLD}NFS / RPC / LDAP / SNMP:${RESET}"
check_tool showmount     "apt install nfs-common"
check_tool rpcinfo       "apt install rpcbind"
check_tool ldapsearch    "apt install ldap-utils"
check_tool snmpwalk      "apt install snmp snmp-mibs-downloader"
check_tool onesixtyone   "apt install onesixtyone"

echo ""
echo -e "${BOLD}Brute forcing:${RESET}"
check_tool hydra         "apt install hydra"
check_tool medusa        "apt install medusa"

echo ""
echo -e "${BOLD}AI (Puter/GPT free fallback):${RESET}"
if command -v node &>/dev/null; then
    good "node: $(node --version)"
    if node -e 'require("@heyputer/puter.js")' 2>/dev/null; then
        good "@heyputer/puter.js: installed"
    else
        warn "@heyputer/puter.js: not installed"
        info "  Installing: npm install -g @heyputer/puter.js"
        npm install -g @heyputer/puter.js 2>/dev/null && good "@heyputer/puter.js: installed" || warn "npm install failed — install manually"
    fi
else
    warn "node: not found (needed for free Puter/GPT AI fallback)"
    info "  Install: apt install nodejs npm"
fi

echo ""
echo -e "${BOLD}Wordlists (recommended):${RESET}"
for wl in /usr/share/wordlists /usr/share/seclists; do
    if [ -d "$wl" ]; then
        good "$wl: present"
    else
        warn "$wl: missing"
    fi
done
info "  Get SecLists: git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists"

# ── Done ──
echo ""
echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
echo ""
echo -e "  Usage:"
echo -e "    ${CYAN}smartnmap <target>${RESET}                   # Quick scan (default)"
echo -e "    ${CYAN}smartnmap <target> --full${RESET}            # Full -p- scan"
echo -e "    ${CYAN}smartnmap <target> --fast${RESET}            # rustscan/masscan acceleration"
echo -e "    ${CYAN}smartnmap <target> --ctf -ai${RESET}         # CTF mode with AI"
echo -e "    ${CYAN}smartnmap <target> --vhosts --markdown${RESET}"
echo -e "    ${CYAN}smartnmap <target>/24${RESET}                # CIDR (host-discovery + scan)"
echo -e "    ${CYAN}smartnmap --install-scripts${RESET}          # Install NSE scripts"
echo ""
echo -e "  Config file for API keys: ${CYAN}~/.config/smartnmap/config.json${RESET}"
echo -e "  Env overrides:            ${CYAN}GEMINI_API_KEY, GEMINI_MODEL${RESET}"
echo -e "  Free AI fallback:         Puter/GPT — just run: ${CYAN}npm install -g @heyputer/puter.js${RESET} (no key needed)"
echo ""
echo -e "  Or run directly:"
echo -e "    ${CYAN}python3 $SMARTNMAP <target>${RESET}"
echo ""
