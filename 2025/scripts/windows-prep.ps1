# Continue on error - don't stop script if something fails
$ErrorActionPreference = "Continue"

$WebClient = New-Object Net.WebClient

# Create tools directory
$Tools = "$env:SystemDrive\Tools"
mkdir "$Tools" -Force -ErrorAction SilentlyContinue

# Binaries - continue on errors
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Rubeus.exe", "$Tools\Rubeus.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/CertificateAbuse/Certify.exe", "$Tools\Certify.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/Enumeration/Seatbelt.exe", "$Tools\Seatbelt.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/GPOAbuse/SharpGPOAbuse.exe", "$Tools\SharpGPOAbuse.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/SharpSCCM.exe", "$Tools\SharpSCCM.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Whisker.exe", "$Tools\Whisker.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/Credentials/SharpDPAPI.exe", "$Tools\SharpDPAPI.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe", "$Tools\SigmaPotato.exe") } catch {}
try { $WebClient.DownloadFile("https://github.com/SnaffCon/Snaffler/releases/download/1.0.170/Snaffler.exe", "$Tools\Snaffler.exe") } catch {}

# Mimikatz
try { $WebClient.DownloadFile("https://github.com/parrotsec/mimikatz/raw/master/x64/mimikatz.exe", "$Tools\mimikatz.exe") } catch {}

# Scripts
try { $WebClient.DownloadFile("https://raw.githubusercontent.com/Commotio/DSInternalsParser/refs/heads/main/dsinternalparser.py", "$Tools\dsinternalparser.py") } catch {}

# PingCastle
try {
    $WebClient.DownloadFile("https://github.com/netwrix/pingcastle/releases/download/3.3.0.0/PingCastle_3.3.0.0.zip", "$Tools\PingCastle.zip")
    Expand-Archive -Path "$Tools\PingCastle.zip" -DestinationPath "$Tools\PingCastle" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$Tools\PingCastle.zip" -Force -ErrorAction SilentlyContinue
} catch {}

# PowerShell scripts
try { $WebClient.DownloadFile("https://github.com/NetSPI/PowerUpSQL/raw/master/PowerUpSQL.ps1", "$Tools\PowerUpSQL.ps1") } catch {}
try { $WebClient.DownloadFile("https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1", "$Tools\PowerView.ps1") } catch {}
try { $WebClient.DownloadFile("https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1", "$Tools\SharpHound.ps1") } catch {}

# RSAT modules (AD PowerShell) and DSInternals
# For Windows Server
try { Get-WindowsFeature -Name RSAT* -ErrorAction SilentlyContinue | Where-Object InstallState -eq 'Available' | Install-WindowsFeature } catch {}

# For Windows 10/11 Client (use Add-WindowsCapability instead)
try { Get-WindowsCapability -Name RSAT* -Online | Where-Object State -ne 'Installed' | Add-WindowsCapability -Online } catch {}

# Install DSInternals module (requires NuGet provider and PSGallery)
try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module DSInternals -Force -ErrorAction SilentlyContinue
} catch {}

# Install Notepad++
try {
    if (-not (Test-Path "$env:ProgramFiles\Notepad++\notepad++.exe")) {
        $WebClient.DownloadFile("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7/npp.8.7.Installer.x64.exe", "$env:USERPROFILE\Downloads\npp.exe")
        Start-Process -FilePath "$env:USERPROFILE\Downloads\npp.exe" -ArgumentList "/S" -Wait
        Remove-Item -Path "$env:USERPROFILE\Downloads\npp.exe" -Force -ErrorAction SilentlyContinue
    }
} catch {}

# Install Python (check if already installed)
try {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        $WebClient.DownloadFile("https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe", "$env:USERPROFILE\Downloads\python.exe")
        Start-Process -FilePath "$env:USERPROFILE\Downloads\python.exe" -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
        Remove-Item -Path "$env:USERPROFILE\Downloads\python.exe" -Force -ErrorAction SilentlyContinue
    }
} catch {}

# Install OpenVPN
try {
    $WebClient.DownloadFile("https://openvpn.net/downloads/openvpn-connect-v3-windows.msi", "$env:USERPROFILE\Downloads\openvpn.msi")
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "$env:USERPROFILE\Downloads\openvpn.msi", "/quiet", "/qn", "/norestart", "AUTOSTART=no" -Wait
    Remove-Item -Path "$env:USERPROFILE\Downloads\openvpn.msi" -Force -ErrorAction SilentlyContinue
} catch {}

# Install MobaXterm
try {
    $WebClient.DownloadFile("https://download.mobatek.net/2422024061715901/MobaXterm_Installer_v24.2.zip", "$env:USERPROFILE\Downloads\MobaXterm.zip")
    Expand-Archive -Path "$env:USERPROFILE\Downloads\MobaXterm.zip" -DestinationPath "$env:USERPROFILE\Downloads\MobaXterm" -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "$env:USERPROFILE\Downloads\MobaXterm\MobaXterm_installer_24.2.msi", "/quiet", "/qn", "/norestart" -Wait
    Remove-Item -Path "$env:USERPROFILE\Downloads\MobaXterm.zip" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\Downloads\MobaXterm" -Recurse -Force -ErrorAction SilentlyContinue
} catch {}

echo "Installation complete!"
