<#
      install vulners.nse + AXISwebcam-enum.nse into nmap database
#>

[CmdletBinding(PositionalBinding=$false)] param(
   [string]$NmapInstallPath="C:\Program Files (x86)\Nmap"
)

$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "@install_nmap_modules > [ v1.0.1 ]"

echo ""
## check for admin privileges
If([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") -match "false")
{
   Write-Host "[ABORT]: administrator privileges required to install nse modules.." -ForegroundColor Red
   return
}

## Vulners
$SuccessfulyInstalledModuleVulners = "false"
if(Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
{
   write-host "[ABORT]: " -NoNewline
   write-host "$NmapInstallPath\scripts\vulners.nse" -ForegroundColor Red -NoNewline
   write-host " already installed"
}
else
{
   Write-Host "[*] downloading: vulners.nse"
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/vulners.nse" -OutFile "$Env:TMP\vulners.nse"|Unblock-File
   Write-Host "[*] move-item: vulners.nse to $NmapInstallPath\scripts\vulners.nse"
   Move-Item -Path "$Env:TMP\vulners.nse" -Destination "$NmapInstallPath\scripts\vulners.nse" -Force

   if(Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
   {
      $SuccessfulyInstalledModuleVulners = "true"
   }
   else
   {
      Write-Host "[-] ERROR: installing vulners.nse" -ForegroundColor Red
      $SuccessfulyInstalledModuleVulners = "false"
   }
}

## AXIS
$SuccessfulyInstalledModuleAxis = "false"
if(Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
{
   write-host "[ABORT]: " -NoNewline
   write-host "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -ForegroundColor Red -NoNewline
   write-host " already installed"
}
else
{
   Write-Host "[*] downloading: AXISwebcam-enum.nse"
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/AXISwebcam-enum.nse" -OutFile "$Env:TMP\AXISwebcam-enum.nse"|Unblock-File
   Write-Host "[*] move-item: AXISwebcam-enum.nse to $NmapInstallPath\scripts\AXISwebcam-enum.nse"
   Move-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Destination "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force

   if(Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
   {
      $SuccessfulyInstalledModuleAxis = "true"
   }
   else
   {
      Write-Host "[-] ERROR: installing AXISwebcam-enum.nse" -ForegroundColor Red
      $SuccessfulyInstalledModuleAxis = "false"
   }
}

## update nse database
If($SuccessfulyInstalledModuleVulners -match "true")
{
   nmap.exe --script-updatedb
   Write-Host "[+] Vulners.nse succeffuly installed"
}
If($SuccessfulyInstalledModuleAxis -match "true")
{
   nmap.exe --script-updatedb
   Write-Host "[+] AXISwebcam-enum.nse succeffuly installed"
}

## cleanup
Remove-Item -Path "$Env:TMP\vulners.nse" -Force
Remove-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Force

echo ""
exit
