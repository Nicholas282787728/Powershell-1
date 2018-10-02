get-aduser -filter 'Name -like "*rura*"'
Get-ADComputer -Filter * -Properties * | Format-Table Name, LastLogonDate -Autosize
Get-ADUser -Identity 'honeypot' | Select-Object SID
Get-ADUser -Identity dlltransfer -Properties whenCreated
Get-ADComputer -Filter * -Properties * | Select-Object -Property name, OperatingSystem, LastLogonDate |Where-Object {$_.Operatingsystem -like "*8.1*"} |Sort-Object -Property OperatingSystem, LastLogonDate | Format-Table -AutoSize
Get-ADuser -Identity pxb -Properties * | more
Get-ADUser user1  | out-string -Stream | Select-String -Pattern "obj"
Get-aduser -filter "department -eq 'marketing' -AND enabled -eq 'True'"
Get-ADComputer -Filter 'Name -like "ahleap*"'
Set-ADAccountExpiration -DateTime "1/8/2018 6:30 PM" -Identity pxb
###### Fri Sep 7 10:47:08 AEST 2018 move computer to OU
$target = Get-ADOrganizationalUnit -LDAPFilter "(name=charlotte)"
get-adcomputer win7-c1 | Move-ADObject -TargetPath $target.DistinguishedName


###### Fri Sep 7 11:01:55 AEST 2018 AD user operation
Set-ADAccountPassword jfrost -NewPassword $newpwd -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True | Unlock-ADAccount
Enable-ADAccount -Identity test

get-aduser richarda -Properties * | Select-Object *lock*
Set-ADAccountPassword richarda -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True | Unlock-ADAccount
###### Fri Sep 7 14:37:57 AEST 2018  get ad group creation date
$GroupList = Get-ADGroup -Filter * -Properties Name, DistinguishedName, GroupCategory, GroupScope, whenCreated, WhenChanged, member, memberOf, sIDHistory, SamAccountName, Description, AdminCount | Select-Object Name, DistinguishedName, GroupCategory, GroupScope, whenCreated, whenChanged, member, memberOf, AdminCount, SamAccountName, Description, `
@{name = 'MemberCount'; expression = {$_.member.count}}, `
@{name = 'MemberOfCount'; expression = {$_.memberOf.count}}, `
@{name = 'SIDHistory'; expression = {$_.sIDHistory -join ','}}, `
@{name = 'DaysSinceChange'; expression = {[math]::Round((New-TimeSpan $_.whenChanged).TotalDays, 0)}} | Sort-Object Name
$GroupList | Select-Object Name, GroupCategory, GroupScope, whenCreated, whenChanged, DaysSinceChange, MemberCount, MemberOfCount, AdminCount, Description, DistinguishedName
Get-ADGroup -Filter * -Properties * | Select-Object -Property name, whencreated, DistinguishedName | Sort-Object whencreated | Out-GridView
New-ADGroup -Name "dwgtrueview" -SamAccountName dwgtrueview -GroupCategory Security -GroupScope Global -Path "OU=Security Groups,OU=MyBusiness,DC=domain,DC=local"
###### Mon Sep 10 11:06:13 AEST 2018  quser and logoff
$userName = 'administrator'
$sessionId = ((quser /server:DC | Where-Object { $_ -match $userName }) -split ' +')[2]
$sessionid


