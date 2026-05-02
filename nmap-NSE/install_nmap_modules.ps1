<#
.SYNOPSIS
   Author: @r00t-3xp10it
   Helper - install vulners.nse + AXISwebcam-enum.nse into nmap database

.NOTES
   Administrator privileges required to install\update modules
   .\install_nmap_modules.ps1 -mode 'install' --> install the two nse scripts in nmap database   
   .\install_nmap_modules.ps1 -mode 'update'  --> update nmap databse with the two scripts again
   .\install_nmap_modules.ps1 -nmapinstallpath 'C:\Nmap\Install\directory' --> nmap install location  
#>

[CmdletBinding(PositionalBinding=$false)] param(
   [string]$NmapInstallPath="C:\Program Files (x86)\Nmap",
   [string]$Mode="install"
)

$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "@install_nmap_nse_modules"

echo ""
## check for admin privileges
If([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") -match "false")
{
   Write-Host "[ABORT]: " -NoNewline
   Write-Host "administrator privileges required to install nse modules..`n" -ForegroundColor Red
   Start-Sleep -Seconds 2
   return
}

## check nmap install directory
If(-not(Test-Path -Path "$NmapInstallPath"))
{
   Write-Host "[ABORT]: nmap directory not found in: $NmapInstallPath" -ForegroundColor Red
   Write-Host "Input nmap directory: " -NoNewline
   $NmapInstallPath = Read-Host
   
   If(-not(Test-Path -Path "$NmapInstallPath"))
   {
      Write-Host "[ABORT]: nmap directory not found in: $NmapInstallPath" -ForegroundColor Red
      return
   }
}

## Install modules
If($Mode -imatch '^(install)$')
{
   Write-Host "[*] installing 2 nmap nse scripts" -ForegroundColor Green
   Start-Sleep -Seconds 1

   ## install Vulners.nse
   if (Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
   {
      write-host "[ABORT]: " -NoNewline
      write-host "$NmapInstallPath\scripts\vulners.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {
      Write-Host "[*] downloading: vulners.nse"
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/vulners.nse" -OutFile "$Env:TMP\vulners.nse"|Unblock-File
      Write-Host "[*] move vulners.nse to $NmapInstallPath\scripts\vulners.nse"
      Move-Item -Path "$Env:TMP\vulners.nse" -Destination "$NmapInstallPath\scripts\vulners.nse" -Force

      if (Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
      {
         Write-Host "[*] moved vulners.nse to nmap scripts directory"
         Write-Host "[+] updating nmap nse database with vulners.nse"
         nmap.exe --script-updatedb
      }
      Else
      {
         Write-Host "[-] ERROR: moving vulners.nse to nmap scripts directory" -ForegroundColor Red
      }
   }

   ## install AXISwebcam-enum.nse
   if (Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
   {
      write-host "[ABORT]: " -NoNewline
      write-host "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {
      Write-Host "[*] downloading: AXISwebcam-enum.nse"
      iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/AXISwebcam-enum.nse" -OutFile "$Env:TMP\AXISwebcam-enum.nse"|Unblock-File
      Write-Host "[*] move AXISwebcam-enum.nse to $NmapInstallPath\scripts\AXISwebcam-enum.nse"
      Move-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Destination "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force

      if (Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
      {
         Write-Host "[*] moved AXISwebcam-enum.nse to nmap scripts directory"
         Write-Host "[+] updating nmap nse database with AXISwebcam-enum.nse"
         nmap.exe --script-updatedb
      }
      Else
      {
         Write-Host "[-] ERROR: moving AXISwebcam-enum.nse to nmap scripts directory" -ForegroundColor Red
      }
   }
}


## update modules
If($Mode -imatch '^(update)$')
{
   Write-Host "[*] updating nmap nse database" -ForegroundColor Green
   Start-Sleep -Seconds 1

   Write-Host "[*] downloading: AXISwebcam-enum.nse"
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/AXISwebcam-enum.nse" -OutFile "$Env:TMP\AXISwebcam-enum.nse"|Unblock-File

   Write-Host "[*] move AXISwebcam-enum.nse to $NmapInstallPath\scripts\AXISwebcam-enum.nse"
   Move-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Destination "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force

  if (Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
  {
     Write-Host "[*] moved AXISwebcam-enum.nse to nmap scripts directory"
     Write-Host "[+] updating nmap nse database with AXISwebcam-enum.nse"
     nmap.exe --script-updatedb
  }
  Else
  {
     Write-Host "[-] ERROR: moving AXISwebcam-enum.nse to nmap scripts directory" -ForegroundColor Red
  }
}

## cleanup
Remove-Item -Path "$Env:TMP\vulners.nse" -Force
Remove-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Force
Start-Sleep -Seconds 4

echo ""
# Here's the command to delete itself.
Remove-Item -Path $MyInvocation.MyCommand.Source
