function reset-password {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$username
    )

    BEGIN {}
    PROCESS {
        $Password = [system.web.security.membership]::GeneratePassword(128, 30)
        $Password
        Set-ADAccountPassword $username -NewPassword $Password -Reset -PassThru | lock-ADAccount
    }
    END {}
}
function remove-groupmember {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$username
    )

    BEGIN {}
    PROCESS {
        $Password = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | Sort-Object {Get-Random})[0..8] -join ''
        Set-ADAccountPassword $username -NewPassword $Password -Reset -PassThru | lock-ADAccount
    }
    END {}
}

Read-Host -Prompt "User Samaccount:" $user
$user
remove-groupmember $user
reset-password $user
