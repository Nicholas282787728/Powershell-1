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
###### Fri Oct 5 19:17:26 AEST 2018
Get-ADComputer -Properties * -Filter  {operatingsystem -like '*server*' -and enabled -eq $true} | Select-Object name, @{n="OU"; e= {$_.canonicalname -replace "/(?!.*/).*",""}},  created, lastlogondate, operatingsystem, operatingsystemservicepack, whenchanged | Sort-Object -Descending lastlogondate | Format-Table -AutoSize
Get-ADComputer -Properties * -Filter  {operatingsystem -like '*server*' -and enabled -eq $true} | Select-Object name, @{n="OU"; e= {$_.canonicalname -replace "/(?!.*/).*",""}}  | Group-Object ou
(Get-ADComputer  -Filter {operatingsystem -like '*server*' -and enabled -eq $true}).name | Get-CimInstance -ClassName win32_operatingsystem | Select-Object pscomputername, InstallDate,LastBootUpTime,OSArchitecture,@{n='OS';e={$_.name -replace "\|.*",""}},Version | Format-Table -AutoSize
###### Thu Oct 11 16:25:20 AEDT 2018  Get all the computers with a name starting by a particular string and showing the name, dns hostname and IPv4 address
Get-ADComputer -Filter 'Name -like "Fabrikam*"' -Properties IPv4Address | Format-Table Name,DNSHostName,IPv4Address -A
###### Thu Oct 11 16:26:11 AEDT 2018
$d = [DateTime]::Today.AddDays(-90); Get-ADComputer -Filter 'PasswordLastSet -ge $d' -Properties PasswordLastSet | Format-Table Name,PasswordLastSet
Write-Host $d
###### Thu Oct 11 16:39:47 AEDT 2018 join pc to domain
Remove-Computer -ComputerName "Computer01" -UnjoinDomaincredential "Domain01\Admin01" -PassThru -Verbose -Restart
Add-Computer -ComputerName "Computer01" -LocalCredential "Computer01\Administrator" -DomainName "Domain01" -Credential "Domain01\Admin01" -Force -Verbose -Restart
###### Wed Oct 17 09:11:45 AEDT 2018 serach account in ou
get-aduser -Filter * -SearchBase "OU=DisabledAccounts, OU=Network Infrastructure Department,OU=Australia,DC=gratex,DC=au"  -properties * |   Sort-Object -Descending LastLogonDate | Format-Table name, lastlogondate
###### Sat Oct 27 14:46:36 AEDT 2018 user lastlogon date
Get-ADUser aloel -Properties * | Select-Object last*
###### Fri Nov 23 21:41:04 AEDT 2018
New-ADGroup -Name "RODC Admins" -SamAccountName RODCAdmins -GroupCategory Security -GroupScope Global -DisplayName "RODC Administrators" -Path "CN=Users,DC=Fabrikam,DC=Com" -Description "des"
###### Fri Nov 23 22:33:19 AEDT 2018 get AD group ou
 (Get-ADGroup group).distinguishedname -replace "^(.*?,)"