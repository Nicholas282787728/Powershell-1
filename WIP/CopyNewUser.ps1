###### Tue Nov 27 15:25:46 AEDT 2018 copy and create new user
[Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
$newusername = read-host  "new user display name - Kalira Afford"
$newusersam = ($newusername.Split(" ")[0] + ($newusername.Split(" ")[1])[0]).ToLower()
$newusersamtemp = Read-Host "New user samaccount [$($newusersam)], enter to use default"
if ($newusersamtemp) {
    if ($newusersamtemp -ne $newusersam) {
        write-host "new user samaccount will be change from $newusersam to $newusersamtemp"-ForegroundColor red
        $newusersam = $newusersamtemp
    }
}
$newusersam + " " + $newusersamtemp

$TextInfo = (Get-Culture).TextInfo
$GivenName = $TextInfo.ToTitleCase($newusername.Split(" ")[0])
$Surname = $TextInfo.ToTitleCase($newusername.Split(" ")[1])

$oldusersam = read-host "old user samaccount - karleyb"
$userinstance = get-aduser $oldusersam -ErrorAction Stop
$upn = ($userinstance.UserPrincipalName).Split("@")[1]
$domain = ((get-addomain).netbiosname)
$Password = [system.web.security.membership]::GeneratePassword(10, 0)
write-host "Password for new user: `n $($password)"

Write-Host "Username: $domain\$newusersam`nPassword: $Password`nDisplayname: $newusername`nGivenname: $($newusername.Split(" ")[0])`nSurename $($newusername.Split(" ")[1])"


#new-aduser -SamAccountName  $newusersam -DisplayName $newusername -Instance $userinstance -name $newusername -UserPrincipalName "$newusersam@$upn" -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -GivenName $GivenName -Surname $GivenName