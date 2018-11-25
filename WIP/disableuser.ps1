function search-user {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$username
    )
    BEGIN {}
    PROCESS {

        $users = get-aduser -filter "samaccountname -like '*$($username)*'"
        switch ($users.count) {
            0 {
                Write-Host "user not found!" -ForegroundColor Red;
                return $false
            }

            {$_ -gt 1} {
                Write-Host "$($users.count) users detected:" -ForegroundColor Red
                $users | Format-Table samaccountname, name, userprincipalname, enabled -AutoSize
                return $false
            }
            default {
                 $users | Format-Table samaccountname, name, userprincipalname, enabled -AutoSize
                return $true
            }
        }
    }
    END {}
}

function reset-password {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$username
    )
    BEGIN {
        [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    }
    PROCESS {
        $Password = [system.web.security.membership]::GeneratePassword(128, 30)
        Set-ADAccountPassword $username -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -Reset -PassThru | Disable-ADAccount
        Write-Host "Password reset to: "  $Password -ForegroundColor Green
    }
    END {}
}
function remove-groupmember {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$username
    )
    BEGIN {}
    PROCESS {
        (Get-ADUser -identity $username -Properties memberof).memberof
        (Get-ADUser -identity $username -Properties memberof).memberof | ForEach-Object {Remove-ADGroupMember -Identity $_ -Members $username -Confirm:$false}
        Disable-ADAccount $username
        Write-Host "user has been removed from all above groups, and account has been disabled" -ForegroundColor Green
    }
    END {}
}
Clear-Host
$user = Read-Host -Prompt "User Account"
$usercount = 1
$users = get-aduser -filter "samaccountname -like '*$($user)*'"
        switch ($users.count) {
            0 {
                Write-Host "user not found!" -ForegroundColor Red;
                $usercount = 0
            }

            {$_ -gt 1} {
                Write-Host "$($users.count) users detected:" -ForegroundColor Red
                $users | Format-Table samaccountname, name, userprincipalname, enabled -AutoSize
                $usercount = $users.count
            }
        }


if ($usercount -eq 1) {
    Write-Host "user account check passed" -ForegroundColor Green
    $users | Format-Table samaccountname, name, userprincipalname, enabled -AutoSize
    write-host "Are you Sure You Want To Disable and Reset $($user) [y to confirm]:"  -ForegroundColor Yellow -BackgroundColor Red
    $confirmation = Read-Host
    if ($confirmation -eq 'y') {
        reset-password $user
        remove-groupmember $user
    }
    else {Write-Host "exit!" -ForegroundColor Red}
}
else {write-host "check failed" -ForegroundColor Red}