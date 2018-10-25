function write-log {
    param (
        $content,
        $logfile
    )
    Write-Output "$("[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)) $content" >> $logfile
}


[string]$rootfolder = "\\ahcad01\300_PRODUCTION\00_JOBS_ACTIVE\"
[string]$destfolder = "D:\Pdf_Server\00001Plans\"
[regex]$regex = '^[0-9*-]+$'
$logfile = "C:\Scripts\Logs\filecompare.log"
$count = 0
$workobjects = Get-ChildItem  $rootfolder | Where-Object {$_.name -match $regex}
foreach ($object in $workobjects) {
    [string]$sourcefile = ($rootfolder + $object + "\output\" + $object + ".pdf")
    [string]$destfile = ($destfolder + $object + "pdf")
    if (Test-Path $sourcefile) {
        if (Test-Path ( $destfolder + $object + ".pdf")) {
            if (((get-item ( $destfolder + $object + ".pdf")).lastwritetime) -ne (Get-Item $sourcefile).LastWriteTime) {
                write-host $object "needs to be updated"
                if ((Get-SmbOpenFile).path -contains $destfile) {
                    Get-SmbOpenFile | Where-Object {$_.path -eq $destfile} | Close-SmbOpenFile -Force
                    Copy-Item $sourcefile -Destination $destfile
                    write-log -logfile $logfile -content "$destfile has been updated"
                }
                $count ++
            }
        }
        else {
            write-host $object "doesn't exist" -BackgroundColor Red
            $count ++
        }
    }
}
Write-Host $count "files need to be updated" -ForegroundColor Yellow