#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/pentoolbox"
LOG="$BASE/install.log"

mkdir -p "$BASE"
touch "$LOG"
: > "$LOG"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()   { echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG"; }
ok()    { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG"; }
fail()  { echo -e "${RED}[X]${NC} $1" | tee -a "$LOG"; }

# ========== Ensure all directories exist ========== #
mkdir -p "$BASE/recon" "$BASE/password" "$BASE/net" "$BASE/wireless" "$BASE/exploitation" "$BASE/wordlists"

# ========== Go version auto-upgrade (if needed) ========== #
check_go_version() {
  local GOV=$(go version | awk '{print $3}' | sed 's/go//')
  if [[ "$GOV" < "1.24" ]]; then
    warn "Go version is $GOV, upgrading to 1.24.5"
    sudo apt remove -y golang-go || true
    wget -q https://go.dev/dl/go1.24.5.linux-arm64.tar.gz -O /tmp/go1.24.5.linux-arm64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go1.24.5.linux-arm64.tar.gz
    if ! grep -Fxq 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' ~/.bashrc; then
      echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    ok "Go upgraded to: $(go version)"
  else
    ok "Go version is up to date: $GOV"
  fi
}
if ! grep -Fxq 'export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"' ~/.bashrc; then
  echo 'export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"' >> ~/.bashrc
fi

echo 'export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

# ========== 1. Recon/OSINT Tools ========== #
HARV="$BASE/recon/theHarvester"
if [ ! -d "$HARV" ]; then
  log "Installing theHarvester in $HARV"
  git clone https://github.com/laramies/theHarvester.git "$HARV"
  cd "$HARV"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  uv sync
else
  ok "theHarvester already installed."
fi
ln -sf "$HARV/theHarvester.py" "$HOME/.local/bin/theHarvester"

# subfinder (Go)
if [ ! -x "$BASE/recon/subfinder" ]; then
  log "Installing subfinder (Go binary)..."
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  mv -f "$HOME/go/bin/subfinder" "$BASE/recon/"
fi
ln -sf "$BASE/recon/subfinder" "$HOME/.local/bin/subfinder"

# nuclei (Go)
if [ ! -x "$BASE/recon/nuclei" ]; then
  log "Installing nuclei (Go binary)..."
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  mv -f "$HOME/go/bin/nuclei" "$BASE/recon/"
fi
ln -sf "$BASE/recon/nuclei" "$HOME/.local/bin/nuclei"

# amass (Snap)
if ! snap list | grep -qw amass; then
  log "Installing amass (Snap)..."
  sudo snap install amass
fi
ln -sf /snap/bin/amass "$BASE/recon/amass"
ln -sf /snap/bin/amass "$HOME/.local/bin/amass"

# recon-ng (APT)
if ! dpkg -s recon-ng &>/dev/null; then
  log "Installing recon-ng (APT)..."
  sudo apt install -y recon-ng
fi
ln -sf "$(command -v recon-ng)" "$BASE/recon/recon-ng"
ln -sf "$(command -v recon-ng)" "$HOME/.local/bin/recon-ng"

# DirBuster install/fix (SourceForge direct extract)
if [ ! -f "$BASE/recon/dirbuster/DirBuster-1.0-RC1.jar" ]; then
  mkdir -p "$BASE/recon/dirbuster"
  cd "$BASE/recon/dirbuster"
  wget https://downloads.sourceforge.net/project/dirbuster/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.bz2 -O DirBuster-1.0-RC1.tar.bz2
  tar xjf DirBuster-1.0-RC1.tar.bz2
# Create launcher wrapper for DirBuster using $BASE
echo -e '#!/usr/bin/env bash\nexec java -jar "$BASE/recon/dirbuster/DirBuster-1.0-RC1.jar" "$@"' > "$HOME/.local/bin/dirbuster"
chmod +x "$HOME/.local/bin/dirbuster"
echo -e '#!/usr/bin/env bash\nexec java -jar "$BASE/recon/dirbuster/DirBuster-1.0-RC1.jar" "$@"' > "$HOME/.local/bin/dirbuster"
chmod +x "$HOME/.local/bin/dirbuster"

# whois (APT)
if ! dpkg -s whois &>/dev/null; then
  sudo apt install -y whois
fi
ln -sf "$(command -v whois)" "$BASE/recon/whois"
ln -sf "$(command -v whois)" "$HOME/.local/bin/whois"

# ========== 2. Password Cracking Tools ========== #
if ! dpkg -s john &>/dev/null; then sudo apt install -y john; fi
ln -sf "$(command -v john)" "$BASE/password/john"
ln -sf "$(command -v john)" "$HOME/.local/bin/john"

if ! dpkg -s hydra &>/dev/null; then sudo apt install -y hydra; fi
ln -sf "$(command -v hydra)" "$BASE/password/hydra"
ln -sf "$(command -v hydra)" "$HOME/.local/bin/hydra"

# ========== 3. Network Analysis Tools ========== #
if ! dpkg -s nmap &>/dev/null; then sudo apt install -y nmap; fi
ln -sf "$(command -v nmap)" "$BASE/net/nmap"
ln -sf "$(command -v nmap)" "$HOME/.local/bin/nmap"

if ! dpkg -s tcpdump &>/dev/null; then sudo apt install -y tcpdump; fi
ln -sf "$(command -v tcpdump)" "$BASE/net/tcpdump"
ln -sf "$(command -v tcpdump)" "$HOME/.local/bin/tcpdump"

if ! dpkg -s netcat-openbsd &>/dev/null; then sudo apt install -y netcat-openbsd; fi
ln -sf "$(command -v nc)" "$BASE/net/netcat"
ln -sf "$(command -v nc)" "$HOME/.local/bin/netcat"

# httpx (Go)
if [ ! -x "$BASE/net/httpx" ]; then
  log "Installing httpx (Go binary)..."
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  mv -f "$HOME/go/bin/httpx" "$BASE/net/"
fi
ln -sf "$BASE/net/httpx" "$HOME/.local/bin/httpx"

# Responder (Python, Git)
RESP="$BASE/net/Responder"
if [ ! -d "$RESP" ]; then
  log "Installing Responder in $RESP"
  git clone https://github.com/lgandx/Responder.git "$RESP"
  pip3 install --user netifaces aioquic impacket cryptography flask ldap3 dnslib dnspython pyOpenSSL
else
  ok "Responder already installed."
fi
ln -sf "$RESP/Responder.py" "$HOME/.local/bin/Responder"

# ========== 4. Exploitation Tools ========== #
if ! snap list | grep -qw metasploit-framework; then
  log "Installing metasploit-framework (Snap)..."
  sudo snap install metasploit-framework
fi
ln -sf /snap/bin/msfconsole "$BASE/exploitation/metasploit"
ln -sf /snap/bin/msfconsole "$HOME/.local/bin/metasploit"

# ========== 5. Wireless/802.11 Exploit Tools ========== #
if ! dpkg -s wireshark &>/dev/null; then
  log "Installing wireshark..."
  sudo apt install -y wireshark
fi
ln -sf "$(command -v wireshark)" "$BASE/wireless/wireshark"
ln -sf "$(command -v wireshark)" "$HOME/.local/bin/wireshark"
ln -sf "$(command -v tshark)" "$BASE/wireless/tshark"
ln -sf "$(command -v tshark)" "$HOME/.local/bin/tshark"

if ! dpkg -s aircrack-ng &>/dev/null; then
  log "Installing aircrack-ng..."
  sudo apt install -y aircrack-ng
fi
for t in aircrack-ng airmon-ng airodump-ng aireplay-ng; do
  ln -sf "$(command -v $t)" "$BASE/wireless/$t"
  ln -sf "$(command -v $t)" "$HOME/.local/bin/$t"
done

if ! dpkg -s hcxdumptool &>/dev/null; then
  sudo apt install -y hcxdumptool
fi
if ! dpkg -s hcxtools &>/dev/null; then
  sudo apt install -y hcxtools
fi
for t in hcxdumptool hcxpcapngtool hcxhashtool hcxcaptool hcxpmkidtool; do
  which "$t" >/dev/null 2>&1 && ln -sf "$(command -v $t)" "$BASE/wireless/$t"
  which "$t" >/dev/null 2>&1 && ln -sf "$(command -v $t)" "$HOME/.local/bin/$t"
done

if ! dpkg -s wifite &>/dev/null; then
  sudo apt install -y wifite
fi
ln -sf "$(command -v wifite)" "$BASE/wireless/wifite"
ln -sf "$(command -v wifite)" "$HOME/.local/bin/wifite"

# ========== 6. Wordlists (SecLists) ========== #
if [ ! -d "$BASE/wordlists/seclists" ]; then
  log "Installing SecLists..."
  git clone https://github.com/danielmiessler/SecLists.git "$BASE/wordlists/seclists"
else
  ok "SecLists already cloned."
fi
ln -sf "$BASE/wordlists/seclists" "$HOME/.local/share/seclists"

# ========== 7. PATH & Aliases ========== #
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"

ALIASES=(
  "alias theharvester='cd \$HOME/pentoolbox/recon/theHarvester && uv run theHarvester'"
  "alias responder='cd \$HOME/pentoolbox/net/Responder && sudo python3 Responder.py -I eth0'"
  "alias subfinder='\$HOME/pentoolbox/recon/subfinder'"
  "alias nuclei='\$HOME/pentoolbox/recon/nuclei'"
  "alias metasploit='/snap/bin/msfconsole'"
)
for alias_line in "${ALIASES[@]}"; do
  if ! grep -Fxq "$alias_line" ~/.bashrc; then
    echo "$alias_line" >> ~/.bashrc
  fi
done

# ========== 8. Status Table (all tools, by folder) ==========
export PATH="$HOME/.local/bin:$PATH"
echo -e "\n${YELLOW}========= Pentoolbox Status =========${NC}"
printf "%-18s %-12s %-32s\n" "Tool" "Status" "Path"
for t in theHarvester subfinder nuclei amass recon-ng dirbuster whois john hydra nmap tcpdump netcat httpx Responder metasploit wireshark tshark aircrack-ng airmon-ng airodump-ng aireplay-ng hcxdumptool hcxpcapngtool hcxhashtool hcxcaptool hcxpmkidtool wifite; do
  pth=$(command -v $t 2>/dev/null || echo "Not in PATH")
  if [[ "$pth" != "Not in PATH" ]]; then
    printf "%-18s ${GREEN}%-12s${NC} %-32s\n" "$t" "OK" "$pth"
  else
    printf "%-18s ${RED}%-12s${NC} %-32s\n" "$t" "FAIL" ""
  fi
done
ok "All tools installed, categorized, and symlinked in \$HOME/.local/bin and \$HOME/pentoolbox. You may need to start a new shell session for PATH and aliases to take effect."
ok "All tools installed, categorized, and symlinked in \$HOME/.local/bin and \$HOME/pentoolbox."