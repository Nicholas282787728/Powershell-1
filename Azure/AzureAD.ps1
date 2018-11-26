###### Mon Nov 26 22:53:49 AEDT 2018 AzureCloud AzureAD Powershell V2.0
connect-azuread -Credential (Import-Clixml -Path C:\temp\azure.cred)
###### Mon Nov 26 22:59:02 AEDT 2018 updated azuread user
Set-AzureADUser -ObjectId leim@esking.org -ShowInAddressList $false
###### Fri Sep 14 13:58:31 AEST 2018 azure      ad sync
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta
Start-ADSyncSyncCycle -PolicyType Initial
