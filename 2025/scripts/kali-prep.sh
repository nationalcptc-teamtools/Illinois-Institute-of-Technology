#!/bin/zsh

# Exit on error
set -e

# Create directories
mkdir -p $HOME/test
mkdir -p $HOME/tools
cd $HOME/tools/

# Sublime APT dependencies
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg --no-check-certificate | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list

# Software upgrade
#sudo hostnamectl set-hostname cyberhawks-linux
#sudo sed -i 's/kali/cyberhawks-linux/g' /etc/hosts
sudo sed -i 's/http.kali.org/mirrors.ocf.berkeley.edu/g' /etc/apt/sources.list
sudo dpkg-reconfigure debconf --frontend=noninteractive
sudo apt -y update
#sudo apt -y upgrade

# Software (APT) packages - FIXED: Added missing tools
sudo apt -y install sublime-text testssl.sh ipmitool python3-venv nfs-common mitm6 git seclists enum4linux-ng pipx rsyslog \
    bloodhound neo4j apt-transport-https jq chromium-browser golang-go mingw-w64 \
    powershell-empire starkiller crackmapexec smbmap redis-tools ldap-utils \
    feroxbuster ffuf gobuster wfuzz sqlmap nikto nuclei \
    powershell powershell-empire gophish wireguard-tools openvpn ncat \
    sshuttle proxychains4 chisel

# Switch default Python to Python 3
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# Python packages - FIXED: Removed duplicate trusted-host flags
pip3 install --upgrade pip --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
echo 'PATH=$HOME/.local/bin:$PATH' >> $HOME/.zshrc
. $HOME/.zshrc
pipx ensurepath

# Core Python tools via pipx
PIP_NO_VERIFY="true" pipx install git+https://github.com/Pennyw0rth/NetExec
PIP_NO_VERIFY="true" pipx install git+https://github.com/p0dalirius/Coercer
PIP_NO_VERIFY="true" pipx install git+https://github.com/garrettfoster13/pre2k
PIP_NO_VERIFY="true" pipx install impacket certipy-ad modbus_cli
PIP_NO_VERIFY="true" pipx inject impacket pyOpenSSL==24.0.0 --force # fix for ntlmrelayx.py --shadowcredentials

# Additional Python tools
PIP_NO_VERIFY="true" pipx install bloodhound pypykatz roadrecon roadtools
PIP_NO_VERIFY="true" pipx install git+https://github.com/dirkjanm/adidnsdump
PIP_NO_VERIFY="true" pipx install git+https://github.com/dirkjanm/ldapdomaindump
PIP_NO_VERIFY="true" pipx install git+https://github.com/Gerenios/AADInternals

# Ruby gems
echo ":ssl_verify_mode: 0" | sudo tee -a /root/.gemrc
sudo gem install evil-winrm winrm winrm-fs

# Standalone Python scripts (coercion tools)
sudo wget https://raw.githubusercontent.com/topotam/PetitPotam/refs/heads/main/PetitPotam.py -O /usr/local/bin/petitpotam --no-check-certificate
sudo chmod +x /usr/local/bin/petitpotam
sudo wget https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/refs/heads/main/dfscoerce.py -O /usr/local/bin/dfscoerce --no-check-certificate
sudo chmod +x /usr/local/bin/dfscoerce
sudo wget https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/refs/heads/main/shadowcoerce.py -O /usr/local/bin/shadowcoerce --no-check-certificate
sudo chmod +x /usr/local/bin/shadowcoerce
sudo wget https://raw.githubusercontent.com/dirkjanm/krbrelayx/refs/heads/master/printerbug.py -O /usr/local/bin/printerbug --no-check-certificate
sudo chmod +x /usr/local/bin/printerbug
sudo wget https://raw.githubusercontent.com/evilashz/CheeseOunce/refs/heads/main/cheese.py -O /usr/local/bin/cheeseounce --no-check-certificate
sudo chmod +x /usr/local/bin/cheeseounce

# Binaries
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute --no-check-certificate
sudo chmod +x /usr/local/bin/kerbrute
sudo wget https://raw.githubusercontent.com/CiscoCXSecurity/rdp-sec-check/master/rdp-sec-check.pl -O /usr/local/bin/rdp-sec-check.pl --no-check-certificate
sudo chmod +x /usr/local/bin/rdp-sec-check.pl
sudo wget https://raw.githubusercontent.com/shifty0g/ultimate-nmap-parser/master/ultimate-nmap-parser.sh -O /usr/local/bin/parse-nmap --no-check-certificate
sudo chmod +x /usr/local/bin/parse-nmap

# Ligolo-ng (pivoting tool)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.6.2_linux_amd64.tar.gz --no-check-certificate
tar -xzf ligolo-ng_agent_0.6.2_linux_amd64.tar.gz
sudo mv agent /usr/local/bin/ligolo-agent
sudo chmod +x /usr/local/bin/ligolo-agent
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz --no-check-certificate
tar -xzf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
sudo mv proxy /usr/local/bin/ligolo-proxy
sudo chmod +x /usr/local/bin/ligolo-proxy
rm -f ligolo-ng_*.tar.gz

# Github packages
git -c http.sslVerify=false clone https://github.com/hsaunders1904/pyautoenv
chmod +x pyautoenv/pyautoenv.plugin.zsh  # FIXED: typo in filename
git -c http.sslVerify=false clone https://github.com/dirkjanm/PKINITtools
git -c http.sslVerify=false clone https://github.com/insidetrust/statistically-likely-usernames
git -c http.sslVerify=false clone https://github.com/dirkjanm/krbrelayx
git -c http.sslVerify=false clone https://github.com/zyn3rgy/LdapRelayScan
git -c http.sslVerify=false clone https://github.com/FortyNorthSecurity/EyeWitness
git -c http.sslVerify=false clone https://github.com/ShutdownRepo/pywhisker
git -c http.sslVerify=false clone https://github.com/GhostPack/Rubeus
git -c http.sslVerify=false clone https://github.com/GhostPack/Seatbelt
git -c http.sslVerify=false clone https://github.com/ly4k/Certipy
git -c http.sslVerify=false clone https://github.com/carlospolop/PEASS-ng
git -c http.sslVerify=false clone https://github.com/internetwache/GitTools
git -c http.sslVerify=false clone https://github.com/swisskyrepo/PayloadsAllTheThings
git -c http.sslVerify=false clone https://github.com/danielmiessler/SecLists
git -c http.sslVerify=false clone https://github.com/PowerShellMafia/PowerSploit
git -c http.sslVerify=false clone https://github.com/samratashok/nishang
git -c http.sslVerify=false clone https://github.com/byt3bl33d3r/OffensiveNim
git -c http.sslVerify=false clone https://github.com/byt3bl33d3r/SprayingToolkit

# Installs
sudo $HOME/tools/EyeWitness/Python/setup/setup.sh
sudo cpan install Encoding::BER

# Install each tool in its own virtual env
find $HOME/tools -type f -name 'requirements.txt' -execdir python3 -m venv .venv \; -execdir .venv/bin/pip install -r {} \;

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
sudo sed -i 's/^strict_chain/#strict_chain/g' /etc/proxychains4.conf
sudo sed -i 's/^#dynamic_chain/dynamic_chain/g' /etc/proxychains4.conf

# Neo4j configuration for BloodHound
sudo systemctl enable neo4j
sudo systemctl start neo4j

. $HOME/.zshrc
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Set Neo4j password: neo4j-admin set-initial-password YourPassword"
echo "2. Start BloodHound: bloodhound"
echo "3. Review installed tools in ~/tools/"
