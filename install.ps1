Set-ExecutionPolicy remotesigned
$tempdir = c:\temp

#copy update package
Set-Location e:\
New-Item -path $tempdir -ItemType Directory
Copy-Item autorun.inf,bootmgr,bootmgr.efi -Destination "C:\temp"
Robocopy.exe .\boot\ c:\temp\boot /E
Robocopy.exe .\efi\ c:\temp\efi /E
Robocopy.exe .\sources c:\temp\sources /E
Robocopy.exe .\support c:\temp\support /E
copy setup.exe c:\temp\setup.exe
Start-Process $tempdir\setup.exe
pause
#xcopy .\setup.exe,autorun.inf,boot\*,bootmgr,bootmgr.efi,efi\*,sources\*,support\* c:\temp /h /e /c
Pause
$software = "e:\!software\"
Set-Location -Path $software
# copy rdp shortcut
Copy-Item -Path .\SVDP\GKO.rdp -Destination C:\Users\Public\Desktop
Pause
#* remove o365 office ##################issue##################

#Get-package -provider programs -includewindowsinstaller -name "*office*" | Uninstall-Package
control appwiz.cpl
Pause
#install office 2010  ##################issue##################
Start-Process -path ".\SVDP\Office2010\setup.exe" -ArgumentList "/adminfile .\svdp\office2010\office.msp" -wait
pause
start-process winword
Pause
#import cert for software download
Import-Certificate -FilePath ".\gratexca.cer" -CertStoreLocation Cert:\LocalMachine\root

Pause
# install necessary software
#start-process -filepath "c:\Program Files\internet explorer\iexplore.exe" -ArgumentList "https://get.adobe.com/reader/"
Copy-Item .\readerdc_en_ra_cra_install.exe $tempdir
Start-Process -FilePath $tempdir\readerdc_en_ra_cra_install.exe

start-process -FilePath ".\Ninite 7Zip Chrome Java 8 TeamViewer 13 Installer.exe"
Pause
# remove vscode
#Get-package -provider programs -includewindowsinstaller -name "*studio code*" | Uninstall-Package
control appwiz.cpl
pause
# time zone and time sync
Set-TimeZone -Name "AUS Eastern Standard Time"
Set-Service w32time -StartupType Automatic
Start-Service w32time
w32tm /resync /force


# windows update 
wuauclt /detectnow
Pause
# remove temp files
Remove-Item C:\temp -Force
Pause