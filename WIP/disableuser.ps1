function search-user {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$username
    )

    BEGIN {}
    PROCESS {
        $users = get-aduser -filter "samaccountname -like '*$($username)*'"
        #$users
        switch ($users.count) {
            0 {Write-Host "user not found!" -ForegroundColor Red; return $false; break }
            1 {$users | ft samaccountname, name, userprincipalname, enabled -AutoSize;return $true ;break}
            default {
              Write-Host "$($users.count) users detected:" -ForegroundColor Red
              $users | ft samaccountname, name, userprincipalname, enabled -AutoSize
              return $false
              break
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
        $Password = [system.web.security.membership]::GeneratePassword(128,30)
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
        (Get-ADUser -identity $username -Properties memberof).memberof | % {Remove-ADGroupMember -Identity $_ -Members $username -Confirm:$false}
        Disable-ADAccount $username
        Write-Host "user has been removed from all groups, and account has been disabled" -ForegroundColor Green
    }
    END {}
}
Clear-Host
$user = Read-Host -Prompt "User Account"
Write-Host "user checked" -ForegroundColor Yellow
$checkresult = search-user $user
$checkresult
if ($checkresult){
    Write-Host "user account check passed" -ForegroundColor Green
    write-host "Are you Sure You Want To Disable and Reset $($user) [y to confirm]:"  -ForegroundColor Yellow -BackgroundColor Red
    $confirmation = Read-Host
    if ($confirmation -eq 'y') {
        reset-password $user
        remove-groupmember $user
    }
    else {Write-Host "exit!" -ForegroundColor Red}
}
else {write-host "check failed" -ForegroundColor Red}