###### Fri Oct 12 11:53:39 AEDT 2018 from
# https://social.technet.microsoft.com/Forums/en-US/f27b0292-6add-40e6-b64b-700b1ff9fe8d/how-can-i-migrate-a-distribution-list-to-a-shared-mailbox-on-my-0365-admin-portal?forum=Exch2016GD
Import-Module activedirectory
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;

#Code written by Jake Bell on the 14th June 2018

#Pull details about the DG to be used
$DG = get-distributiongroup -identity (Read-Host -Prompt 'Input the Distribution Group Name')
$DGM = Get-DistributionGroupMember -Identity $DG | Select-Object Name,primarysmtpaddress
$X500 = $DG.legacyexchangedn
$x500 = "x500:" + $x500

#delete the DG
Remove-DistributionGroup -Identity $dg

#create the shared mailbox with same details as the DG
new-mailbox -Name $dg -alias $DG.PrimarySmtpAddress.local -shared -primarysmtpaddress $dg.PrimarySmtpAddress.Local+"@"+$dg.PrimarySmtpAddress.Domain

#Create x500 address for anyone with autocomplete
set-mailbox -identity $DG.PrimarySmtpAddress.local -EmailAddresses @{Add= $x500}

#Sent items correction
set-mailbox -identity $DG.PrimarySmtpAddress.local -MessageCopyForSendOnBehalfEnabled:$true -MessageCopyForSentAsEnabled:$true

#add full access to the original members
foreach ($primarysmtpaddress in $DGM)
{
Add-MailboxPermission -Identity $DG.PrimarySmtpAddress.local -User $primarysmtpaddress.PrimarySmtpAddress.Address -AccessRights FullAccess -InheritanceType All
Add-ADPermission -Identity $DG.name -user $primarysmtpaddress.PrimarySmtpAddress.Address -AccessRights ExtendedRight -ExtendedRights "Send As"
}

write-host "Completed the script"