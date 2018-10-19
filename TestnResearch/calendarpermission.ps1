$rptCollection = @()

$mailboxes = get-mailbox -ResultSize Unlimited

$mailboxes | foreach-object{

$alias = $_.alias + ":\Calendar"

$displayName = $_.DisplayName

write-host $alias

$permissions = Get-MailboxFolderPermission $alias | Where-Object {$_.Identity.ToString() -ne "Default"}

if($permissions -ne $null){

$stringPerms = ""

foreach($perms in $permissions.AccessRights){$stringPerms = $stringPerms + $perms + " "}

Add-Member -InputObject $permissions -MemberType NoteProperty -Name "Alias" -Value $alias -Force

Add-Member -InputObject $permissions -MemberType NoteProperty -Name "StringAccessRights" -Value $stringPerms -Force

$rptCollection += $permissions

}

}

$rptCollection | export-csv -notypeInformation c:\test.csv

﻿Then to import the calender permissions I would run this command

import-csv c:\test.csv | foreach-object{

"Seting Rights on " + $_.alias

Set-MailboxFolderPermission -id $_.alias -User $_.Identity -AccessRights $_.StringAccessRights

}

