##########  exchange ###############

Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;

# Get-MailboxFolderPermission -identity “Managingdirector:\Calendar” 
Get-Mailbox  *killara*


Get-DistributionGroup *shseas*  | get-DistributionGroupMember

Get-DistributionGroup *shseas* | Remove-DistributionGroupMember -Member Gisellet

Add-MailboxFolderPermission -Identity "Pennyb:\calendar" -user kritiy -AccessRights reviewer

#########################################    DC   ####################
Enter-PSSession sadc01
Get-ADGroup -Filter 'name -like "*car*"' | Select-Object name
# ACL_Dolores_CarsCalendar
# ACL_Killara_CarsCalendar
Add-ADGroupMember -Identity ACL_Dolores_CarsCalendar -Members kritiy


