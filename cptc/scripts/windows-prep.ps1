$WebClient = New-Object Net.WebClient

# Create tools directory
$Tools = "$env:SystemDrive\Tools"
mkdir "$Tools"

# Binaries
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Rubeus.exe", "$Tools\Rubeus.exe")
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/CertificateAbuse/Certify.exe", "$Tools\Certify.exe")
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/Enumeration/Seatbelt.exe", "$Tools\Seatbelt.exe")
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/GPOAbuse/SharpGPOAbuse.exe", "$Tools\SharpGPOAbuse.exe")
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/SharpSCCM.exe", "$Tools\SharpSCCM.exe")
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Whisker.exe", "$Tools\Whisker.exe")
$WebClient.DownloadFile("https://github.com/jakobfriedl/precompiled-binaries/raw/main/Credentials/SharpDPAPI.exe", "$Tools\SharpDPAPI.exe")
$WebClient.DownloadFile("https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe", "$Tools\SigmaPotato.exe")
$WebClient.DownloadFile("https://github.com/SnaffCon/Snaffler/releases/download/1.0.170/Snaffler.exe", "$Tools\Snaffler.exe")

# Scripts
$WebClient.DownloadFile("https://raw.githubusercontent.com/Commotio/DSInternalsParser/refs/heads/main/dsinternalparser.py", "$Tools\dsinternalsparser.py")

# PingCastle
$WebClient.DownloadFile("https://github.com/netwrix/pingcastle/releases/download/3.3.0.0/PingCastle_3.3.0.0.zip", "$Tools\PingCastle.zip")
Expand-Archive -Path "$Tools\PingCastle.zip" -DestinationPath "$Tools\PingCastle"
Remove-Item -Path "$Tools\PingCastle.zip"

# PowerShell scripts
$WebClient.DownloadFile("https://github.com/NetSPI/PowerUpSQL/raw/master/PowerUpSQL.ps1", "$Tools\PowerUpSQL.ps1")
$WebClient.DownloadFile("https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1", "$Tools\PowerView.ps1")

# RSAT modules (AD PowerShell) and DSInternals
Get-WindowsFeature -Name RSAT* | Where-Object InstallState -eq 'Available' | Install-WindowsFeature
Install-Module DSInternals -Force

# Install Notepad++
$WebClient.DownloadFile("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7/npp.8.7.Installer.x64.exe", "$env:USERPROFILE\Downloads\npp.exe")
Start-Process -FilePath "$env:USERPROFILE\Downloads\npp.exe" -ArgumentList "/S" -Wait
Remove-Item -Path "$env:USERPROFILE\Downloads\npp.exe" -Force

# Install Python
$WebClient.DownloadFile("https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe", "$env:USERPROFILE\Downloads\python.exe")
Start-Process -FilePath "$env:USERPROFILE\Downloads\python.exe" -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
Remove-Item -Path "$env:USERPROFILE\Downloads\python.exe" -Force

# Install OpenVPN
$WebClient.DownloadFile("https://openvpn.net/downloads/openvpn-connect-v3-windows.msi", "$env:USERPROFILE\Downloads\openvpn.msi")
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "$env:USERPROFILE\Downloads\openvpn.msi", "/quiet", "/qn", "/norestart", "AUTOSTART=no" -Wait
#msiexec /i "$env:USERPROFILE\Downloads\openvpn.msi" /quiet /qn /norestart AUTOSTART=no
Remove-Item -Path "$env:USERPROFILE\Downloads\openvpn.msi" -Force

# Install MobaXterm
$WebClient.DownloadFile("https://download.mobatek.net/2422024061715901/MobaXterm_Installer_v24.2.zip", "$env:USERPROFILE\Downloads\MobaXterm.zip")
Expand-Archive -Path "$env:USERPROFILE\Downloads\MobaXterm.zip" -DestinationPath "$env:USERPROFILE\Downloads\MobaXterm"
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "$env:USERPROFILE\Downloads\MobaXterm\MobaXterm_installer_24.2.msi", "/quiet", "/qn", "/norestart" -Wait
#msiexec /i "$env:USERPROFILE\Downloads\MobaXterm\MobaXterm_installer_24.2.msi" /quiet /qn /norestart
Remove-Item -Path "$env:USERPROFILE\Downloads\MobaXterm.zip" -Force
Remove-Item -Path "$env:USERPROFILE\Downloads\MobaXterm" -Recurse -Force

echo "Installation complete!"