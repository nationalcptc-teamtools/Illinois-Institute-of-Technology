#!/bin/zsh

# Continue on error - don't exit if something fails
set +e

# Create directories
mkdir -p $HOME/test
mkdir -p $HOME/tools
cd $HOME/tools/

# Passwordless sudo for the sudo group (attacker/lab box convenience).
# Written as a validated drop-in in /etc/sudoers.d rather than editing /etc/sudoers
# directly, since a syntax error in the main file can lock you out of sudo entirely.
echo '%sudo ALL=(ALL:ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/99-nopasswd-sudo > /dev/null || true
sudo chmod 440 /etc/sudoers.d/99-nopasswd-sudo || true
# Validate the drop-in; if it is somehow invalid, remove it rather than risk breaking sudo
sudo visudo -cf /etc/sudoers.d/99-nopasswd-sudo || sudo rm -f /etc/sudoers.d/99-nopasswd-sudo

# Sublime Text APT repository (required for the sublime-text package below)
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg --no-check-certificate | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null || true
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list || true

# Software upgrade
#sudo hostnamectl set-hostname cyberhawks-linux
#sudo sed -i 's/kali/cyberhawks-linux/g' /etc/hosts
sudo sed -i 's/http.kali.org/mirrors.ocf.berkeley.edu/g' /etc/apt/sources.list
export DEBIAN_FRONTEND=noninteractive
sudo dpkg-reconfigure debconf --frontend=noninteractive
sudo apt -y update
#sudo apt -y upgrade

# Software (APT) packages - essential tools only
sudo apt -y install python3-venv nfs-common mitm6 git enum4linux-ng pipx rsyslog || true
sudo apt -y install bloodhound neo4j jq crackmapexec smbmap ldap-utils || true
sudo apt -y install ffuf gobuster sqlmap || true
sudo apt -y install proxychains4 sshuttle openvpn || true
sudo apt -y install sublime-text magic-wormhole krb5-user freerdp3-x11 rdate testssl.sh ipmitool seclists || true

# Switch default Python to Python 3
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# Python packages - FIXED: Removed duplicate trusted-host flags
pip3 install --upgrade pip --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
echo 'PATH=$HOME/.local/bin:$PATH' >> $HOME/.zshrc
. $HOME/.zshrc
pipx ensurepath

# Core Python tools via pipx - continue on errors
PIP_NO_VERIFY="true" pipx install git+https://github.com/Pennyw0rth/NetExec || true
PIP_NO_VERIFY="true" pipx install git+https://github.com/p0dalirius/Coercer || true
PIP_NO_VERIFY="true" pipx install git+https://github.com/garrettfoster13/pre2k || true
PIP_NO_VERIFY="true" pipx install git+https://github.com/garrettfoster13/sccmhunter || true
PIP_NO_VERIFY="true" pipx install impacket certipy-ad modbus_cli || true
PIP_NO_VERIFY="true" pipx inject impacket pyOpenSSL==24.0.0 --force || true # fix for ntlmrelayx.py --shadowcredentials

# Additional Python tools
# NOTE: pipx 'bloodhound' is the Python collector/ingestor (bloodhound-python),
# not the BloodHound CE app - that comes from the apt 'bloodhound' package above.
PIP_NO_VERIFY="true" pipx install bloodhound pypykatz || true

# Go toolchain (official release - apt's golang-go lags too far behind for some tools to build)
GO_VERSION=$(curl -sL https://go.dev/VERSION?m=text | head -n1)
wget -qO /tmp/go.tar.gz "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz" --no-check-certificate || true
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz || true
rm -f /tmp/go.tar.gz
echo 'PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> $HOME/.zshrc
export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH

# Go modules
go install github.com/sensepost/gowitness@latest || true
go install -ldflags="-s -w" -trimpath "github.com/FalconOpsLLC/goexec@latest" || true

# Ruby gems
echo ":ssl_verify_mode: 0" | sudo tee -a /root/.gemrc || true
sudo gem install evil-winrm winrm winrm-fs || true

# Standalone Python scripts (coercion tools)
sudo wget https://raw.githubusercontent.com/topotam/PetitPotam/refs/heads/main/PetitPotam.py -O /usr/local/bin/petitpotam --no-check-certificate || true
sudo chmod +x /usr/local/bin/petitpotam || true
sudo wget https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/refs/heads/main/dfscoerce.py -O /usr/local/bin/dfscoerce --no-check-certificate || true
sudo chmod +x /usr/local/bin/dfscoerce || true
sudo wget https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/refs/heads/main/shadowcoerce.py -O /usr/local/bin/shadowcoerce --no-check-certificate || true
sudo chmod +x /usr/local/bin/shadowcoerce || true
sudo wget https://raw.githubusercontent.com/dirkjanm/krbrelayx/refs/heads/master/printerbug.py -O /usr/local/bin/printerbug --no-check-certificate || true
sudo chmod +x /usr/local/bin/printerbug || true
sudo wget https://raw.githubusercontent.com/evilashz/CheeseOunce/refs/heads/main/cheese.py -O /usr/local/bin/cheeseounce --no-check-certificate || true
sudo chmod +x /usr/local/bin/cheeseounce || true

# Binaries
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute --no-check-certificate || true
sudo chmod +x /usr/local/bin/kerbrute || true
sudo wget https://raw.githubusercontent.com/CiscoCXSecurity/rdp-sec-check/master/rdp-sec-check.pl -O /usr/local/bin/rdp-sec-check.pl --no-check-certificate || true
sudo chmod +x /usr/local/bin/rdp-sec-check.pl || true
sudo wget https://raw.githubusercontent.com/RhinoSecurityLabs/Security-Research/master/tools/python/CVE-2005-1794-check.py -O /usr/local/bin/CVE-2005-1794-check.py --no-check-certificate || true
sudo chmod +x /usr/local/bin/CVE-2005-1794-check.py || true
sudo wget https://raw.githubusercontent.com/shifty0g/ultimate-nmap-parser/master/ultimate-nmap-parser.sh -O /usr/local/bin/parse-nmap --no-check-certificate || true
sudo chmod +x /usr/local/bin/parse-nmap || true

# Ligolo-ng (pivoting tool) - proxy only
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz --no-check-certificate || true
tar -xzf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz || true
sudo mv proxy /usr/local/bin/ligolo-proxy || true
sudo chmod +x /usr/local/bin/ligolo-proxy || true
rm -f ligolo-ng_*.tar.gz || true

# Github packages - essential tools only
git -c http.sslVerify=false clone https://github.com/hsaunders1904/pyautoenv || true
chmod +x pyautoenv/pyautoenv.plugin.zsh || true
git -c http.sslVerify=false clone https://github.com/dirkjanm/PKINITtools || true
git -c http.sslVerify=false clone https://github.com/dirkjanm/krbrelayx || true
git -c http.sslVerify=false clone https://github.com/ShutdownRepo/pywhisker || true
git -c http.sslVerify=false clone https://github.com/insidetrust/statistically-likely-usernames || true
git -c http.sslVerify=false clone https://github.com/Ridter/noPac || true

# Perl module dependencies (for rdp-sec-check.pl)
sudo cpan install Encoding::BER || true
sudo cpan install Net::Pcap || true

# Install each cloned tool's Python dependencies in its own virtual env
# (pyautoenv, configured below, auto-activates these .venv dirs on cd)
find $HOME/tools -type f -name 'requirements.txt' -execdir python3 -m venv .venv \; -execdir .venv/bin/pip install -r {} \; || true

# Custom zshrc - FIXED: Better prompt with network interface detection
cat >> $HOME/.zshrc << 'EOF'
# clear without clearing history
alias clear='clear -x'

# auto activate python virtual environments
source $HOME/tools/pyautoenv/pyautoenv.plugin.zsh

# better terminal prompt with dynamic interface detection
get_ip() {
    # Try common interfaces in order
    for iface in tun0 eth0 ens33 eth1; do
        ip=$(ip -4 addr show $iface 2>/dev/null | awk '/inet /{print $2}' | cut -d'/' -f1)
        if [[ -n "$ip" ]]; then
            echo "$iface: $ip"
            return
        fi
    done
    echo "no ip"
}

IP='$(get_ip)'

PROMPT=$'%F{%(#.blue.green)}┌──${debian_chroot:+($debian_chroot)──}(%B%F{%(#.red.blue)}%n%(#.💀.㉿)%m%b%F{%(#.blue.green)})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]%F{green} ['"$IP"$']\n└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
RPROMPT=$'%(?.. %? %F{red}%B⨯%b%F{reset})%(1j. %j %F{yellow}%B⚙%b%F{reset}.)'

# Useful aliases
alias ll='ls -lah'
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias serve='python3 -m http.server'
alias myip='curl -s ifconfig.me'
EOF

# Root zshrc
echo -e "# clear without clearing history\nalias clear='clear -x'\n# auto activate python virtual environments\nsource $HOME/tools/pyautoenv/pyautoenv.plugin.zsh" | sudo tee -a /root/.zshrc

# Configure logging
sudo sh -c "echo 'local6.*    /var/log/commands.log' >> /etc/rsyslog.d/commands.conf"
echo 'precmd() { eval RETRN_VAL=$?;logger -p local6.debug "$(whoami) [$$]: $(history | tail -n1 | sed "s/^[ ]*[0-9]\+[ ]*//" ) [$RETRN_VAL]" }' >> $HOME/.zshrc
echo 'precmd() { eval RETRN_VAL=$?;logger -p local6.debug "$(whoami) [$$]: $(history | tail -n1 | sed "s/^[ ]*[0-9]\+[ ]*//" ) [$RETRN_VAL]" }' | sudo tee -a /root/.zshrc
sudo systemctl restart rsyslog

# Configure proxychains
sudo sed -i 's/^strict_chain/#strict_chain/g' /etc/proxychains4.conf || true
sudo sed -i 's/^#dynamic_chain/dynamic_chain/g' /etc/proxychains4.conf || true

# BloodHound CE setup (Kali's 'bloodhound' package is now BloodHound Community Edition).
# bloodhound-setup initializes neo4j + postgresql and writes /etc/bhapi/bhapi.json, so there
# is no need to enable/start neo4j by hand. Start/stop later with bloodhound-start/-stop
# (the old standalone 'bloodhound' command is deprecated in favor of bloodhound-start).
sudo bloodhound-setup || true

. $HOME/.zshrc
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Start BloodHound:  sudo bloodhound-start   (stop with: sudo bloodhound-stop)"
echo "2. Neo4j console:     http://localhost:7474   (first login neo4j/neo4j - set a new password)"
echo "3. If you change the Neo4j password, update /etc/bhapi/bhapi.json to match"
echo "4. BloodHound UI login defaults to admin/admin - set a new password on first login"
echo "5. Review installed tools in ~/tools/"
