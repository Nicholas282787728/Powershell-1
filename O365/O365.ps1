Get-Credential | Export-Clixml -Path C:\temp\azure.cred
###### Mon Nov 26 12:06:37 AEDT 2018 o365 password never expired
Connect-MsolService -Credential (Import-Clixml -Path C:\temp\azure.cred)
get-msoluser -UserPrincipalName test@abc.com | Format-List pass*
set-MsolUser -UserPrincipalName test@abc.com  -PasswordNeverExpires $true
###### Mon Nov 26 22:21:07 AEDT 2018 sync error troubleshooting
Get-MsolDirSyncProvisioningError -ErrorCategory PropertyConflict -PropertyName UserPrincipalName
Get-MsolDirSyncProvisioningError -ErrorCategory PropertyConflict -MaxResults 5
###### Mon Nov 26 22:21:27 AEDT 2018 o365 licensing
Get-MsolAccountSku
Get-MsolUser -UserPrincipalName $user
Get-MsolUser -All  | Where-Object {$_.isLicensed -eq $true}
###### Mon Nov 26 22:24:53 AEDT 2018 remove user licenses
$user = "leim@esking.org"
$lic =  (Get-MsolUser -UserPrincipalName $user).Licenses[0].AccountSkuId
Set-MsolUserLicense -UserPrincipalName $user -RemoveLicenses $lic
# add licenses
Set-MsolUserLicense -UserPrincipalName $user -AddLicenses $lic
###### Mon Nov 26 22:47:51 AEDT 2018 block sign in
Set-MsolUser -UserPrincipalName leim@esking.org -BlockCredential $true
# check status of dir sync
(Get-MsolCompanyInformation).directorysynchronizationenabled
Set-MsolDirSyncEnabled -EnableDirSync $true