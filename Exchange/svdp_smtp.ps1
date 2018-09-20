<# $smtpServer = "ho-ex2010-caht1.exchangeserverpro.net"
$smtpFrom = "reports@exchangeserverpro.net"
$smtpTo = $to
$messageSubject = $subject
$messageBody = $body


 test

Send-MailMessage -To $to -From $form -Subject $subject

 #>


$SG2data = '{0:N2}' -f (( Get-ChildItem S:\SG2Data\98BB8CED-5E2A-4E23-9D6D-D537BC006A2612.3.Single -recurse | Measure-Object -Property Length -Sum).Sum /1GB)
$sgdata = '{0:N2}' -f (( Get-ChildItem Q:\SGDATA\3C6C019B-598A-4A7F-82A6-4CE28532739F12.2.Single -recurse | Measure-Object -Property Length -Sum).Sum /1GB)


$From = "user1@company.org"
$To = "leim@company.com.au"
$Cc = "leim@company.comau"
$Attachment = "C:\users\Username\Documents\SomeTextFile.txt"
$subject=  "SG2Data indexing is $($SG2data)GB, SGData indexing is $($sgdata)GB"
$Body = "This is what I want to say"
$SMTPServer = "smtp.google.com"
$SMTPPort = "587"
#Send-MailMessage -From $From -to $To -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl -Credential (Get-Credential) -Attachments $Attachment –DeliveryNotificationOption OnSuccess
Send-MailMessage -From $From -to $To -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl –DeliveryNotificationOption OnSuccess


