###### Mon Nov 26 22:21:07 AEDT 2018 sync error troubleshooting
Get-MsolDirSyncProvisioningError -ErrorCategory PropertyConflict -PropertyName UserPrincipalName
Get-MsolDirSyncProvisioningError -ErrorCategory PropertyConflict -MaxResults 5
###### Mon Nov 26 22:21:27 AEDT 2018 o365 licensing
Get-MsolAccountSku
Get-MsolUser -UserPrincipalName $user
Get-MsolUser -All  | where {$_.isLicensed -eq $true}
###### Mon Nov 26 22:24:53 AEDT 2018 remove user licenses
$user = "leim@esking.org"
$lic =  (Get-MsolUser -UserPrincipalName $user).licenses.accountskuid
Set-MsolUserLicense -UserPrincipalName $user -RemoveLicenses $lic
# add licenses
Set-MsolUserLicense -UserPrincipalName $user -AddLicenses $lic

