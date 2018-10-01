$cred=Get-Credential
Connect-MsolService -Credential $cred

# check status of dir sync
(Get-MsolCompanyInformation).directorysynchronizationenabled

Set-MsolDirSyncEnabled -EnableDirSync $true




