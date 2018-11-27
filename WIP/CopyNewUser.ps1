###### Tue Nov 27 15:25:46 AEDT 2018 copy and create new user
[Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
$newusername = read-host  "new user display name - Kalira Afford"
$newusersam = ($newusername.Split(" ")[0] + ($newusername.Split(" ")[1])[0]).ToLower()
$newusersamtemp = Read-Host "New user samaccount [$($newusersam)], enter to use default"
$domain = ((get-addomain).netbiosname)
$givenname = ($newusername.Split(" ")[0])

if ($newusersamtemp) {
    if ($newusersamtemp -ne $newusersam) {
        write-host "new user samaccount will be change from $newusersam to $newusersamtemp"-ForegroundColor red
        $newusersam = $newusersamtemp
    }
}
$newusersam + " " + $newusersamtemp

$oldusersam = read-host "old user samaccount - karleyb"
$userinstance = get-aduser $oldusersam -ErrorAction Stop
$upn = ($userinstance.UserPrincipalName).Split("@")[1]
$Password = [system.web.security.membership]::GeneratePassword(10, 0)
write-host "Password for new user: `n $($password)"

Write-Host "Username: $domain\$newusersam`nPassword: $Password`nDisplayname: $newusername`nGivenname: $($newusername.Split(" ")[0])`nSurename $($newusername.Split(" ")[1])"


new-aduser -SamAccountName  $newusersam -DisplayName $newusername -Instance $userinstance -name $newusername -UserPrincipalName "$newusersam@$upn" -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -GivenName $newusername.Split(" ")[0] -Surname $newusername.Split(" ")[1]