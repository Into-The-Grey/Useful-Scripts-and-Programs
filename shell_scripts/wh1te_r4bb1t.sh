#!/usr/bin/env bash
set -euo pipefail

# Configuration
BASE="$HOME/pentoolbox"
LOG="$BASE/install.log"
MAX_RETRIES=3
RETRY_DELAY=5

# Color codes
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# Ensure base directory exists
mkdir -p "$BASE"
touch "$LOG"
: > "$LOG"

# Trap to handle script interruption
cleanup_on_exit() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo -e "\n${RED}[X]${NC} Script interrupted or failed. Check $LOG for details."
    echo -e "${YELLOW}[!]${NC} Partial installation may be present in $BASE"
  fi
  exit $exit_code
}
trap cleanup_on_exit EXIT INT TERM

# Logging functions
log()   { echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG"; }
ok()    { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG"; }
fail()  { echo -e "${RED}[X]${NC} $1" | tee -a "$LOG"; exit 1; }

# Utility functions
retry_command() {
  local cmd="$1"
  local description="$2"
  local retries=0
  
  while [ $retries -lt $MAX_RETRIES ]; do
    if eval "$cmd"; then
      return 0
    else
      retries=$((retries + 1))
      if [ $retries -lt $MAX_RETRIES ]; then
        warn "Failed to $description (attempt $retries/$MAX_RETRIES). Retrying in ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
      else
        fail "Failed to $description after $MAX_RETRIES attempts"
      fi
    fi
  done
}

check_and_install_deps() {
  local deps=("curl" "wget" "git" "python3" "pip3" "java" "snapd")
  local missing_deps=()
  
  log "Checking dependencies..."
  
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
      missing_deps+=("$dep")
    fi
  done
  
  # Special check for snap command availability
  if ! command -v snap &>/dev/null && systemctl is-active --quiet snapd; then
    missing_deps+=("snapd")
  fi
  
  if [ ${#missing_deps[@]} -ne 0 ]; then
    log "Installing missing dependencies: ${missing_deps[*]}"
    retry_command "sudo apt update" "update package list"
    retry_command "sudo apt install -y ${missing_deps[*]}" "install dependencies"
    
    # Enable snapd if it was installed
    if [[ " ${missing_deps[*]} " =~ " snapd " ]]; then
      sudo systemctl enable --now snapd
      sudo systemctl enable --now snapd.socket
    fi
  else
    ok "All dependencies are already installed"
  fi
}

add_to_bashrc() {
  local line="$1"
  if ! grep -Fxq "$line" ~/.bashrc; then
    echo "$line" >> ~/.bashrc
    log "Added to ~/.bashrc: $line"
  fi
}

detect_architecture() {
  local arch=$(uname -m)
  case $arch in
    x86_64) echo "linux-amd64" ;;
    aarch64|arm64) echo "linux-arm64" ;;
    *) fail "Unsupported architecture: $arch" ;;
  esac
}

create_symlink() {
  local source="$1"
  local target="$2"
  
  # Create target directory if it doesn't exist
  mkdir -p "$(dirname "$target")"
  
  if [ -e "$source" ] || [ -L "$source" ]; then
    ln -sf "$source" "$target"
    return 0
  else
    warn "Source file does not exist: $source"
    return 1
  fi
}

# Rollback function for failed installations
rollback_on_failure() {
  local tool_name="$1"
  local install_path="$2"
  
  warn "Rolling back failed installation of $tool_name"
  rm -rf "$install_path" 2>/dev/null || true
  rm -f "$HOME/.local/bin/$tool_name" 2>/dev/null || true
}

# Check if running as root (not recommended)
check_user() {
  if [ "$EUID" -eq 0 ]; then
    fail "This script should not be run as root. Please run as a regular user with sudo privileges."
  fi
  
  if ! sudo -n true 2>/dev/null; then
    warn "This script requires sudo privileges. You may be prompted for your password."
  fi
}

# ========== Initialization ========== #
log "Starting pentoolbox installation..."
check_user
check_and_install_deps

# Ensure all directories exist
mkdir -p "$BASE/recon" "$BASE/password" "$BASE/net" "$BASE/wireless" "$BASE/exploitation" "$BASE/wordlists" "$HOME/.local/bin"

# ========== Go version check and upgrade ========== #
check_go_version() {
  if ! command -v go &>/dev/null; then
    warn "Go not found, installing Go 1.24.5"
    install_go
    return
  fi
  
  local GOV=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//' || echo "0")
  if [[ "$GOV" < "1.24" ]]; then
    warn "Go version is $GOV, upgrading to 1.24.5"
    install_go
  else
    ok "Go version is up to date: $GOV"
  fi
}

install_go() {
  local arch=$(detect_architecture)
  local go_tar="go1.24.5.$arch.tar.gz"
  local go_url="https://go.dev/dl/$go_tar"
  
  # Remove existing Go installation
  sudo apt remove -y golang-go &>/dev/null || true
  sudo rm -rf /usr/local/go
  
  # Download and install Go with retry
  retry_command "wget -q '$go_url' -O '/tmp/$go_tar'" "download Go"
  sudo tar -C /usr/local -xzf "/tmp/$go_tar"
  rm -f "/tmp/$go_tar"
  
  # Update PATH
  add_to_bashrc 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  
  if command -v go &>/dev/null; then
    ok "Go installed successfully: $(go version)"
  else
    fail "Go installation failed"
  fi
}

# Initialize Go
check_go_version

# Setup PATH
add_to_bashrc 'export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"'
export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

# ========== 1. Recon/OSINT Tools ========== #
install_theharvester() {
  local HARV="$BASE/recon/theHarvester"
  if [ ! -d "$HARV" ]; then
    log "Installing theHarvester in $HARV"
    retry_command "git clone https://github.com/laramies/theHarvester.git '$HARV'" "clone theHarvester"
    
    cd "$HARV" || fail "Failed to change directory to $HARV"
    
    # Install uv if not available
    if ! command -v uv &>/dev/null; then
      log "Installing uv package manager..."
      retry_command "curl -LsSf https://astral.sh/uv/install.sh | sh" "install uv"
      # Source the cargo env to get uv in PATH
      [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
      export PATH="$HOME/.cargo/bin:$PATH"
    fi
    
    # Try uv first, fallback to pip
    if command -v uv &>/dev/null; then
      if retry_command "uv sync" "sync theHarvester dependencies"; then
        ok "theHarvester dependencies installed with uv"
      else
        warn "uv sync failed, trying pip fallback"
        retry_command "pip3 install -r requirements.txt --user" "install theHarvester requirements with pip"
      fi
    else
      warn "uv not available, using pip fallback"
      retry_command "pip3 install -r requirements.txt --user" "install theHarvester requirements with pip"
    fi
    
    cd "$BASE" || fail "Failed to return to base directory"
    ok "theHarvester installed successfully"
  else
    ok "theHarvester already installed."
  fi
  
  create_symlink "$HARV/theHarvester.py" "$HOME/.local/bin/theHarvester"
}

install_go_tool() {
  local tool_name="$1"
  local tool_path="$2"
  local category="${3:-recon}"
  local install_path="$BASE/$category/$tool_name"
  
  if [ ! -x "$install_path" ]; then
    log "Installing $tool_name (Go binary)..."
    
    # Check if Go is available
    if ! command -v go &>/dev/null; then
      fail "Go is not installed or not in PATH. Cannot install $tool_name"
    fi
    
    if retry_command "go install $tool_path@latest" "install $tool_name"; then
      if [ -f "$HOME/go/bin/$tool_name" ]; then
        mv "$HOME/go/bin/$tool_name" "$install_path"
        ok "$tool_name installed successfully"
      else
        warn "$tool_name binary not found after installation, trying alternative location"
        # Some Go tools install with different names or paths
        local alt_binary=$(find "$HOME/go/bin" -name "*$tool_name*" -type f | head -1)
        if [ -n "$alt_binary" ]; then
          mv "$alt_binary" "$install_path"
          ok "$tool_name installed successfully (found at alternative location)"
        else
          rollback_on_failure "$tool_name" "$install_path"
          fail "$tool_name binary not found after installation"
        fi
      fi
    else
      rollback_on_failure "$tool_name" "$install_path"
    fi
  else
    ok "$tool_name already installed"
  fi
  
  create_symlink "$install_path" "$HOME/.local/bin/$tool_name"
}

# Install tools
install_theharvester
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# amass (Snap)
install_amass() {
  if ! snap list 2>/dev/null | grep -qw amass; then
    log "Installing amass (Snap)..."
    retry_command "sudo snap install amass" "install amass"
  else
    ok "amass already installed"
  fi
  
  create_symlink "/snap/bin/amass" "$BASE/recon/amass"
  create_symlink "/snap/bin/amass" "$HOME/.local/bin/amass"
}

# recon-ng (APT)
install_recon_ng() {
  if ! dpkg -s recon-ng &>/dev/null; then
    log "Installing recon-ng (APT)..."
    retry_command "sudo apt update && sudo apt install -y recon-ng" "install recon-ng"
  else
    ok "recon-ng already installed"
  fi
  
  local recon_path=$(command -v recon-ng)
  if [ -n "$recon_path" ]; then
    create_symlink "$recon_path" "$BASE/recon/recon-ng"
    create_symlink "$recon_path" "$HOME/.local/bin/recon-ng"
  fi
}

# DirBuster install/fix (SourceForge direct extract)
install_dirbuster() {
  local dirbuster_dir="$BASE/recon/dirbuster"
  local jar_file="$dirbuster_dir/DirBuster-1.0-RC1.jar"
  
  if [ ! -f "$jar_file" ]; then
    log "Installing DirBuster..."
    mkdir -p "$dirbuster_dir"
    cd "$dirbuster_dir"
    
    local url="https://downloads.sourceforge.net/project/dirbuster/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.bz2"
    retry_command "wget -q '$url' -O DirBuster-1.0-RC1.tar.bz2" "download DirBuster"
    
    if ! tar xjf DirBuster-1.0-RC1.tar.bz2; then
      fail "Failed to extract DirBuster archive"
    fi
    
    rm -f DirBuster-1.0-RC1.tar.bz2
    cd "$BASE"
    ok "DirBuster installed successfully"
  else
    ok "DirBuster already installed"
  fi
  
  # Create launcher wrapper for DirBuster
  local launcher="$HOME/.local/bin/dirbuster"
  cat > "$launcher" << 'EOF'
#!/usr/bin/env bash
exec java -jar "$HOME/pentoolbox/recon/dirbuster/DirBuster-1.0-RC1.jar" "$@"
EOF
  chmod +x "$launcher"
}

# whois (APT)
install_whois() {
  if ! dpkg -s whois &>/dev/null; then
    log "Installing whois..."
    retry_command "sudo apt install -y whois" "install whois"
  else
    ok "whois already installed"
  fi
  
  local whois_path=$(command -v whois)
  if [ -n "$whois_path" ]; then
    create_symlink "$whois_path" "$BASE/recon/whois"
    create_symlink "$whois_path" "$HOME/.local/bin/whois"
  fi
}

# Install recon tools
install_amass
install_recon_ng
install_dirbuster
install_whois

# ========== 2. Password Cracking Tools ========== #
install_apt_tool() {
  local tool_name="$1"
  local category="$2"
  
  if ! dpkg -s "$tool_name" &>/dev/null; then
    log "Installing $tool_name..."
    retry_command "sudo apt install -y $tool_name" "install $tool_name"
  else
    ok "$tool_name already installed"
  fi
  
  local tool_path=$(command -v "$tool_name")
  if [ -n "$tool_path" ]; then
    create_symlink "$tool_path" "$BASE/$category/$tool_name"
    create_symlink "$tool_path" "$HOME/.local/bin/$tool_name"
  fi
}

install_apt_tool "john" "password"
install_apt_tool "hydra" "password"

# ========== 3. Network Analysis Tools ========== #
install_apt_tool "nmap" "net"
install_apt_tool "tcpdump" "net"

# netcat (special case)
if ! dpkg -s netcat-openbsd &>/dev/null; then
  log "Installing netcat-openbsd..."
  retry_command "sudo apt install -y netcat-openbsd" "install netcat"
else
  ok "netcat already installed"
fi

local nc_path=$(command -v nc)
if [ -n "$nc_path" ]; then
  create_symlink "$nc_path" "$BASE/net/netcat"
  create_symlink "$nc_path" "$HOME/.local/bin/netcat"
fi

# httpx (Go)
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx" "net"

# Responder (Python, Git)
install_responder() {
  local RESP="$BASE/net/Responder"
  if [ ! -d "$RESP" ]; then
    log "Installing Responder in $RESP"
    retry_command "git clone https://github.com/lgandx/Responder.git '$RESP'" "clone Responder"
    
    log "Installing Responder Python dependencies..."
    local pip_deps="netifaces aioquic impacket cryptography flask ldap3 dnslib dnspython pyOpenSSL"
    retry_command "pip3 install --user $pip_deps" "install Responder dependencies"
    
    ok "Responder installed successfully"
  else
    ok "Responder already installed."
  fi
  
  create_symlink "$RESP/Responder.py" "$HOME/.local/bin/Responder"
}

install_responder

# ========== 4. Exploitation Tools ========== #
install_metasploit() {
  if ! snap list 2>/dev/null | grep -qw metasploit-framework; then
    log "Installing metasploit-framework (Snap)..."
    retry_command "sudo snap install metasploit-framework" "install metasploit"
  else
    ok "metasploit already installed"
  fi
  
  create_symlink "/snap/bin/msfconsole" "$BASE/exploitation/metasploit"
  create_symlink "/snap/bin/msfconsole" "$HOME/.local/bin/metasploit"
}

install_metasploit

# ========== 5. Wireless/802.11 Exploit Tools ========== #
install_wireless_tools() {
  # Install wireshark
  if ! dpkg -s wireshark &>/dev/null; then
    log "Installing wireshark..."
    # Pre-configure wireshark to avoid interactive prompts
    echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
    retry_command "sudo apt install -y wireshark" "install wireshark"
  else
    ok "wireshark already installed"
  fi
  
  local wireshark_path=$(command -v wireshark)
  local tshark_path=$(command -v tshark)
  
  if [ -n "$wireshark_path" ]; then
    create_symlink "$wireshark_path" "$BASE/wireless/wireshark"
    create_symlink "$wireshark_path" "$HOME/.local/bin/wireshark"
  fi
  
  if [ -n "$tshark_path" ]; then
    create_symlink "$tshark_path" "$BASE/wireless/tshark"
    create_symlink "$tshark_path" "$HOME/.local/bin/tshark"
  fi
  
  # Install aircrack-ng suite
  install_apt_tool "aircrack-ng" "wireless"
  
  # Create symlinks for aircrack-ng tools
  for t in airmon-ng airodump-ng aireplay-ng; do
    local tool_path=$(command -v "$t")
    if [ -n "$tool_path" ]; then
      create_symlink "$tool_path" "$BASE/wireless/$t"
      create_symlink "$tool_path" "$HOME/.local/bin/$t"
    fi
  done
  
  # Install hcx tools
  for tool in hcxdumptool hcxtools; do
    if ! dpkg -s "$tool" &>/dev/null; then
      log "Installing $tool..."
      retry_command "sudo apt install -y $tool" "install $tool"
    else
      ok "$tool already installed"
    fi
  done
  
  # Create symlinks for hcx tools
  for t in hcxdumptool hcxpcapngtool hcxhashtool hcxcaptool hcxpmkidtool; do
    if command -v "$t" &>/dev/null; then
      local tool_path=$(command -v "$t")
      create_symlink "$tool_path" "$BASE/wireless/$t"
      create_symlink "$tool_path" "$HOME/.local/bin/$t"
    fi
  done
  
  # Install wifite
  install_apt_tool "wifite" "wireless"
}

install_wireless_tools

# ========== 6. Wordlists (SecLists) ========== #
install_seclists() {
  local seclists_dir="$BASE/wordlists/seclists"
  if [ ! -d "$seclists_dir" ]; then
    log "Installing SecLists..."
    retry_command "git clone https://github.com/danielmiessler/SecLists.git '$seclists_dir'" "clone SecLists"
    ok "SecLists installed successfully"
  else
    ok "SecLists already cloned."
  fi
  
  create_symlink "$seclists_dir" "$HOME/.local/share/seclists"
}

install_seclists

# ========== 7. PATH & Aliases ========== #
setup_aliases() {
  log "Setting up aliases..."
  
  local aliases=(
    "alias theharvester='cd \$HOME/pentoolbox/recon/theHarvester && uv run theHarvester'"
    "alias responder='cd \$HOME/pentoolbox/net/Responder && sudo python3 Responder.py -I eth0'"
    "alias subfinder='\$HOME/pentoolbox/recon/subfinder'"
    "alias nuclei='\$HOME/pentoolbox/recon/nuclei'"
    "alias metasploit='/snap/bin/msfconsole'"
  )
  
  for alias_line in "${aliases[@]}"; do
    add_to_bashrc "$alias_line"
  done
}

setup_aliases

# ========== 8. Status Table (all tools, by folder) ==========
generate_status_report() {
  log "Generating final status report..."
  echo -e "\n${YELLOW}========= Pentoolbox Status =========${NC}"
  printf "%-18s %-12s %-32s\n" "Tool" "Status" "Path"
  echo "--------------------------------------------------------------"
  
  local tools=(
    "theHarvester" "subfinder" "nuclei" "amass" "recon-ng" "dirbuster" "whois"
    "john" "hydra" "nmap" "tcpdump" "netcat" "httpx" "Responder" "metasploit"
    "wireshark" "tshark" "aircrack-ng" "airmon-ng" "airodump-ng" "aireplay-ng"
    "hcxdumptool" "hcxpcapngtool" "hcxhashtool" "hcxcaptool" "hcxpmkidtool" "wifite"
  )
  
  local success_count=0
  local total_count=${#tools[@]}
  
  for tool in "${tools[@]}"; do
    local pth=$(command -v "$tool" 2>/dev/null || echo "Not in PATH")
    if [[ "$pth" != "Not in PATH" ]] && [ -x "$pth" ]; then
      printf "%-18s ${GREEN}%-12s${NC} %-32s\n" "$tool" "OK" "$pth"
      ((success_count++))
    else
      printf "%-18s ${RED}%-12s${NC} %-32s\n" "$tool" "FAIL" "Not found"
    fi
  done
  
  echo "--------------------------------------------------------------"
  echo -e "${BLUE}Summary: ${GREEN}$success_count${NC}/${BLUE}$total_count${NC} tools successfully installed"
  
  if [ $success_count -eq $total_count ]; then
    ok "All tools installed successfully!"
  else
    warn "Some tools failed to install. Check the log at $LOG for details."
  fi
}

cleanup_installation() {
  log "Cleaning up temporary files..."
  # Clean up any temporary downloads
  rm -f /tmp/go*.tar.gz /tmp/DirBuster*.tar.bz2
  
  # Set proper permissions
  chmod -R 755 "$BASE" 2>/dev/null || true
  chmod 755 "$HOME/.local/bin/"* 2>/dev/null || true
}

# Final steps
cleanup_installation
generate_status_report

ok "Pentoolbox installation completed!"
ok "Tools are organized in $BASE and symlinked in \$HOME/.local/bin"
ok "Please run 'source ~/.bashrc' or start a new shell session for PATH and aliases to take effect."

echo -e "\n${YELLOW}Quick Start:${NC}"
echo "  • All tools are available in your PATH"
echo "  • Tool categories: recon, password, net, wireless, exploitation, wordlists"  
echo "  • Log file: $LOG"
echo "  • To use aliases: source ~/.bashrc"