$folder = 'C:\Temp\folder'
$result = dir $folder -Recurse | Measure-Object length -Sum | % {
    New-Object psobject -prop @{
        Name = $folder
        Size = $(
            switch ($_.sum) {
                {$_ -gt 1tb} { '{0:N2}TB' -f ($_ / 1tb); break }
                {$_ -gt 1gb} { '{0:N2}GB' -f ($_ / 1gb); break }
                {$_ -gt 1mb} { '{0:N2}MB' -f ($_ / 1mb); break }
                {$_ -gt 1kb} { '{0:N2}KB' -f ($_ / 1Kb); break }
                default { '{0}B ' -f $_ }
            }
        )
    }
}

$result | ft -AutoSize