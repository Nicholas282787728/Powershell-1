###### Tue Nov 27 15:25:46 AEDT 2018 copy and create new user
[Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
$newusername = read-host  "new user display name - eg. [Lei Miao]"
$newusersam = ($newusername.Split(" ")[0] + ($newusername.Split(" ")[1])[0]).ToLower()
$newusersamtemp = Read-Host "New user samaccount [$($newusersam)], or enter another one"
if ($newusersamtemp) {
    if ($newusersamtemp -ne $newusersam) {
        write-host "new user samaccount will be change from $newusersam to $newusersamtemp"-ForegroundColor red
        $newusersam = $newusersamtemp
    }
}
#$newusersam + " " + $newusersamtemp
$TextInfo = (Get-Culture).TextInfo
$GivenName = $TextInfo.ToTitleCase($newusername.Split(" ")[0])
$Surname = $TextInfo.ToTitleCase($newusername.Split(" ")[1])
$newusername = $TextInfo.ToTitleCase($newusername)
$oldusersam = read-host "Old user samaccount - [leim]"
$userinstance = get-aduser $oldusersam -ErrorAction Stop
$upn = ($userinstance.UserPrincipalName).Split("@")[1]
$domain = ((get-addomain).netbiosname)
$Password = [system.web.security.membership]::GeneratePassword(10, 0)

  try {
        Get-ADUser -Identity $newusersam -ErrorAction Stop
    }
    catch {
        if ($_ -like "*Cannot find an object with identity: '$newusersam'*") {
            #"User '$u' does not exist."
            $message = "`r`n`r`nUsername: $domain\$newusersam`r`nPassword: $Password`r`nUserPrincipalName: $newusersam@$upn`r`nDisplayname: $newusername`r`nGivenname: $givenname`r`nSurename $surname`r`n`r`n"
            Write-Host $message

            if ((Read-Host "confirm to create new account [y]") -eq "y"){
                new-aduser -SamAccountName  $newusersam -DisplayName $newusername -Instance $userinstance -name $newusername -UserPrincipalName "$newusersam@$upn" -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -GivenName $GivenName -Surname $Surname -Enabled $true
                get-aduser -Identity $newusersam
                $message | Set-Clipboard -Confirm
            }
        }
        else {
            "An error occurred: $_"
            "User '$($newusersam)' already exists."
        }
        continue
    }
Write-Host "User '$($newusersam)' already exists." -ForegroundColor Red