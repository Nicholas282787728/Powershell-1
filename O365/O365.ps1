###### Mon Nov 26 12:06:37 AEDT 2018 o365 password never expired
Connect-MsolService
get-msoluser -UserPrincipalName test@abc.com | fl pass*
set-MsolUser -UserPrincipalName test@abc.com  -PasswordNeverExpires $true
