function write-log {
    param (
        [string]$content,
        [string]$logfile
    )
    Add-Content -Path $logfile -Value "$("[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)) $content"
}


[string]$sourcefolder = "\\ahcad01\300_PRODUCTION\00_JOBS_ACTIVE\"
[string]$destfolder = "D:\Pdf_Server\00001Plans\"
[regex]$regex = '^[0-9*-]+$'
$logfile = "C:\Scripts\Logs\filecompare.log"
$count = 0
$size = 0
$workobjects = Get-ChildItem  $sourcefolder | Where-Object {$_.name -match $regex}

#write-log -logfile $logfile -content "###START###"

foreach ($object in $workobjects) {
    [string]$sourcefile = ($sourcefolder + $object + "\output\" + $object + ".pdf")
    [string]$destfile = ($destfolder + $object + ".pdf")
    if (Test-Path $sourcefile) {
        if (Test-Path $destfile) {
            if (((get-item $destfile).lastwritetime) -ne (Get-Item $sourcefile).LastWriteTime) {
                write-host $object "needs to be updated"
                if ((Get-SmbOpenFile).path -contains $destfile) {
                    Get-SmbOpenFile | Where-Object {$_.path -eq $destfile} | Close-SmbOpenFile -Force
                    #write-log -logfile $logfile -content "$destfile has been updated"
                }
                Copy-Item $sourcefile -Destination $destfile
                $count ++
                $size += (get-item $sourcefile).Length
            }
        }
        else {
            write-host $object "doesn't exist" -BackgroundColor Red
            $count ++
            Copy-Item $sourcefile -Destination $destfile
        }
    }
}

Write-Host "$count files need to be updated, $('{0:N2}' -f ($size/1mb))MB" -ForegroundColor Yellow