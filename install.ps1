Set-ExecutionPolicy RemoteSigned -Force
# create temp folder
$tempdir = "c:\temp"
#New-Item -path $tempdir -ItemType Directory

If (!(test-path $tempdir)) {
    New-Item -ItemType Directory -Force -Path $tempdir
}

#copy update package
$uroot = $PSScriptRoot.substring(0, 2)

$SubFolders = "boot\", "efi\", "sources\", "support\"
ForEach ($folder in $SubFolders) {
    #Write-Host $uroot\$folder
    Copy-Item -Path $uroot\$folder -Destination $tempdir -Recurse -Force
}
#Invoke-Command -ComputerName $compname -ScriptBlock {param($folders,$paste) Copy-Item -Path $folders -Destination $paste} -ArgumentList $folders, $paste

Copy-Item $uroot\setup.exe, $uroot\autorun.inf, $uroot\bootmgr, $uroot\bootmgr.efi -Destination $tempdir
Start-Process $tempdir\setup.exe
Pause

# setup working dir
$software = "$($uroot)\!software"
# copy rdp shortcut
Copy-Item -Path $software\company\GKO.rdp -Destination C:\Users\Public\Desktop
Pause
# remove o365 office #!#################issue##################

Get-package -provider programs -includewindowsinstaller -name "*office*" | Uninstall-Package
control appwiz.cpl
Pause

#install office 2010
Start-Process -wait -nonewwindow $software\company\Office2010\setup.exe -ArgumentList '/adminfile', "$($software)\company\company.msp"
pause

start-process winword
Pause

#import cert for software download
Import-Certificate -FilePath "$software\ca.cer" -CertStoreLocation Cert:\LocalMachine\root
Pause

# install necessary software
Copy-Item $software\readerdc_en_ra_cra_install.exe $tempdir
Start-Process -wait -FilePath $tempdir\readerdc_en_ra_cra_install.exe
Pause
start-process -FilePath "$software\Ninite 7Zip Chrome Java 8 TeamViewer 13 Installer.exe"
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
Remove-Item C:\temp -Recurse -Force
Pause

Stop-Computer -Force