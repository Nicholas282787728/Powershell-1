$cred=Get-Credential
Connect-MsolService -Credential $cred

# check status of dir sync
(Get-MsolCompanyInformation).directorysynchronizationenabled

Set-MsolDirSyncEnabled -EnableDirSync $true

###### Fri Sep 14 13:58:31 AEST 2018 ad sync
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta
Start-ADSyncSyncCycle -PolicyType Initial


###### Fri Sep 14 14:17:07 AEST 2018 o365 powershell###### Mon Sep 17 08:45:16 AEST 2018
Install-Module -Name AzureAD
Connect-AzureAD
Connect-MsolService