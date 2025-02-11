$ascii0 = @"
 _______ _    _ ______   ____       _______ _______ _      ______   ________     ________ 
|__   __| |  | |  ____| |  _ \   /\|__   __|__   __| |    |  ____| |  ____\ \   / /  ____|
   | |  | |__| | |__    | |_) | /  \  | |     | |  | |    | |__    | |__   \ \_/ /| |__   
   | |  |  __  |  __|   |  _ < / /\ \ | |     | |  | |    |  __|   |  __|   \   / |  __|  
   | |  | |  | | |____  | |_) / ____ \| |     | |  | |____| |____  | |____   | |  | |____ 
   |_|  |_|  |_|______| |____/_/    \_\_|     |_|  |______|______| |______|  |_|  |______|



"@

$ascii1 = @"
  _____  _____  __          __  _______ _____ _    _ _____ _   _  _____ 
 |_   _|/ ____| \ \        / /\|__   __/ ____| |  | |_   _| \ | |/ ____|
   | | | (___    \ \  /\  / /  \  | | | |    | |__| | | | |  \| | |  __ 
   | |  \___ \    \ \/  \/ / /\ \ | | | |    |  __  | | | | .   | | |_ |
  _| |_ ____) |    \  /\  / ____ \| | | |____| |  | |_| |_| |\  | |__| |
 |_____|_____/      \/  \/_/    \_\_|  \_____|_|  |_|_____|_| \_|\_____|



"@

$ascii2 = @"
  _____   _____     _____  _____          _   _ _   _ ______ _____  
 |  __ \ / ____|   / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
 | |__) | |       | (___ | |       /  \  |  \| |  \| | |__  | |  | |
|  ___/| |        \___ \| |      / /\ \ | .   | .   |  __| | |  | |
 | |    | |____    ____) | |____ / ____ \| |\  | |\  | |____| |__| |
 |_|     \_____|  |_____/ \_____/_/    \_\_| \_|_| \_|______|_____/ 



"@

$ascii3 = @"
  __  __          _____  ______    ______     __   __  __      __     ___    _ _____            
 |  \/  |   /\   |  __ \|  ____|  |  _ \ \   / /  |  \/  |   /\\ \   / / |  | |  __ \     /\    
 | \  / |  /  \  | |  | | |__     | |_) \ \_/ /   | \  / |  /  \\ \_/ /| |  | | |__) |   /  \   
 | |\/| | / /\ \ | |  | |  __|    |  _ < \   /    | |\/| | / /\ \\   / | |  | |  _  /   / /\ \  
 | |  | |/ ____ \| |__| | |____   | |_) | | |     | |  | |/ ____ \| |  | |__| | | \ \  / ____ \ 
 |_|  |_/_/    \_\_____/|______|  |____/  |_|     |_|  |_/_/    \_\_|   \____/|_|  \_\/_/    \_\



"@



function Strip-ANSI {
    param([string]$txt)
    $ansi = [regex]"\x1B[@-_][0-?]*[ -/]*[@-~]"
    return $ansi.Replace($txt, "")
}



function Center-Text {
    param([string]$txt)
    
    $columns  = [System.Console]::WindowWidth
    $lines    = $txt -split "`n"
    
    foreach ($line in $lines) {
        $stripped  = Strip-ANSI $line
        $padding   = [math]::Floor(($columns - $stripped.Length) / 2)
        

        if ($padding -lt 0) {
            $padding = 0
        }
        
        Write-Host (" " * $padding + $line) -NoNewline  -ForegroundColor Cyan
        Write-Host $end
    }
}



function Format-Output {
    param($name, $value)
    $output = "{0} : {1}" -f $name, $value -replace 'System.Byte\[\]', ''
    
    if ($output -notmatch "Steam|Origin|EAPlay|FileSyncConfig.exe|OutlookForWindows") {
        return $output
    }
}



function Scan-PC {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $secureBootState = Confirm-SecureBootUEFI
           
            if ($secureBootState) {
                Write-Host " `n    {x} Secure Boot is" -ForegroundColor Cyan -NoNewline; Write-Host " ON" -ForegroundColor Green
           
            } else {
                Write-Host " `n    {x} Secure Boot is" -ForegroundColor Cyan -NoNewline; Write-Host " OFF" -ForegroundColor Red
            }
      
        } else {
            Write-Host " `n    {x} Secure Boot not available on this system." -ForegroundColor Yellow
        }
   
    } catch {
        Write-Host " `n    {x} Unable to retrieve Secure Boot status: $_" -ForegroundColor Red
    }



    Write-Host "    {x} Finding" -ForegroundColor Cyan -NoNewline; Write-Host " Windows install" -ForegroundColor White -NoNewline; Write-Host " date" -ForegroundColor Cyan
    $os           = Get-WmiObject -Class Win32_OperatingSystem
    $installDate  = $os.ConvertToDateTime($os.InstallDate)
   
    $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
    $global:logEntries += " `nWindows Installation Date: $installDate"



    Write-Host " `n    {x} " -ForegroundColor Cyan -NoNewline; Write-Host " Looking for .tlscan" -ForegroundColor White -NoNewline; Write-Host " folders" -ForegroundColor Cyan
    $recentDocsPath  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $tlscanFound     = $false
   
    if (Test-Path $recentDocsPath) {
        $recentDocs = Get-ChildItem -Path $recentDocsPath
        
        foreach ($item in $recentDocs) {
            if ($item.PSChildName -match "\.tlscan") {
                $tlscanFound  = $true
                $folderPath   = Get-ItemProperty -Path "$recentDocsPath\$($item.PSChildName)" -Name MRUListEx
                $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
                $global:logEntries += ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath"
                Write-Host ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath" -ForegroundColor Red
            }
        }
    }
  
    if (-not $tlscanFound) {
        Write-Host "    {x}" -ForegroundColor Cyan -NoNewline; Write-Host " No .tlscan ext found" -ForegroundColor Green
    }



    Write-Host " `n    {x} Scanning Registry" -ForegroundColor Cyan
    $loggedPaths   = @{}
    $registryPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $userSettings  = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }

    if ($userSettings) {
        foreach ($setting in $userSettings) {
            $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
            $global:logEntries += " `n$($setting.PSPath)"
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
           
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name) -and $item.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                    $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
                    $global:logEntries += " `n" + (Format-Output $item.Name $item.Value)
                    $loggedPaths[$item.Name] = $true
                }
            }
        }
  
    } else {
        Write-Host "    {x} No relevant user settings found." -ForegroundColor Red
    }


    $compatRegistryPath  = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    $compatEntries       = Get-ItemProperty -Path $compatRegistryPath
    
    $compatEntries.PSObject.Properties | ForEach-Object {
        if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
            $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
            $global:logEntries += " `n" + (Format-Output $_.Name $_.Value)
            $loggedPaths[$_.Name] = $true
        }
    }


    $newRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    
    if (Test-Path $newRegistryPath) {
        $newEntries = Get-ItemProperty -Path $newRegistryPath
        $newEntries.PSObject.Properties | ForEach-Object {
           
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
                $global:logEntries += " `n" + (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }


    $muiCachePath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    
    if (Test-Path $muiCachePath) {
        $muiCacheEntries = Get-ChildItem -Path $muiCachePath
        $muiCacheEntries.PSObject.Properties | ForEach-Object {
           
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
                $global:logEntries += " `n" + (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }
    $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
    $global:logEntries = $global:logEntries | Sort-Object | Get-Unique | Where-Object { $_ -notmatch "\{.*\}" } | ForEach-Object { $_ -replace ":", "" }



    Write-Host "    {x} Scanning Prefetch" -ForegroundColor Cyan
    $prefetchPath = "C:\Windows\Prefetch"

    if (Test-Path $prefetchPath) {
        $pfFiles = Get-ChildItem -Path $prefetchPath -Filter *.pf -File
      
        if ($pfFiles.Count -gt 0) {
            $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`nPrefetch Files`n"
           
            $pfFiles | ForEach-Object {
                $logEntry = "{0} | {1}" -f $_.Name, $_.LastWriteTime
                $global:logEntries += " `n" + $logEntry
            }
       
        } else {
            Write-Host "    {x}" -ForegroundColor Cyan -NoNewline; Write-Host " No .pf files found" -ForegroundColor Green
        }
   
    } else {
        Write-Host "    {!} Prefetch folder not found." -ForegroundColor Red
    }


    Write-Host "    {x} Looking for loaders" -ForegroundColor Cyan
    $susFiles = @()

    foreach ($file in $global:logEntries) {
        if ($file -match "loader.*\.exe") { $susFiles += $file }
    }

    if ($susFiles.Count -gt 0) {
        $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n Loader Files`n"
        $global:logEntries += " `n$susFiles" | Sort-Object
    }


    Write-Host "    {x} Looking for compressed files" -ForegroundColor Cyan
    $zipRarFiles = @()
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $uniquePaths = @{}

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -Include *.zip, *.rar -File
            
            foreach ($file in $files) {
                if (-not $uniquePaths.ContainsKey($file.FullName) -and $file.FullName -notmatch "minecraft") {
                    $uniquePaths[$file.FullName] = $true
                    $zipRarFiles += $file
                }
            }
        }
    }

    if ($zipRarFiles.Count -gt 0) {
        $global:logEntries += " `n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ `n"
        $global:logEntries += "Found .zip and .rar files:"
        $zipRarFiles | ForEach-Object { $global:logEntries += " `n" + $_.FullName }
    }



    Write-Host "    {x} Looking for deleted files" -ForegroundColor Cyan
    $tempPath         = [System.IO.Path]::GetTempPath()
    $deletedFileName  = "$env:UserName-deleted.txt"
    $deletedFilePath  = Join-Path -Path $tempPath -ChildPath $deletedFileName

    fsutil usn readjournal c: csv | findstr /1 /c:.exe 2>$null | findstr /1 /c:0x80000200 2>$null >>$deletedFilePath



    $accountPath    = "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\settings"
    $accounts       = Get-ChildItem -Path $accountPath -File
    $foundAccounts  = $accounts.Count
    Write-Host "    {x}" -ForegroundColor Cyan -NoNewline; Write-Host " $foundAccounts Account(s) found" -ForegroundColor Green

    foreach ($file in $accounts) {
        $formattedLink = "https://r6.tracker.network/r6siege/profile/ubi/$($file.Name)"
        Start-Process $formattedLink
    }

}



function Send-Logs {
    $tempPath         = [System.IO.Path]::GetTempPath()
    $currentUser      = $env:UserName
    $logFileName      = "$currentUser-log.txt"
    $deletedFileName  = "$currentUser-deleted.txt"
    $logFilePath      = Join-Path -Path $tempPath -ChildPath $logFileName
    $deletedFilePath  = Join-Path -Path $tempPath -ChildPath $deletedFileName
    $ipAddress        = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip

    if (Test-Path $logFilePath) {
        $url = "https://ptb.discord.com/api/webhooks/1316160688162603090/HPXs2uyzRi2JAWOaU7eFNpJnXc8kqjuUMAJRjmSxMsp5j26P-w4jxfcjo0IgP_G3ej2X"

        $pcUsername       = $env:UserName
        $systemName       = $env:COMPUTERNAME
        $hardwareId       = (Get-WmiObject -Query "Select * from Win32_ComputerSystemProduct").UUID
        $currentDateTime  = Get-Date -Format "MM/dd/yyyy hh:mm tt"

        $embed = @{
            username  = "Pc Checker"
            content   = ""
            embeds    = @(
                @{
                    title   = "PC Check Logs"
                    color   = 00000000
                    fields  = @(
                        @{
                            name    = "User"
                            value   = $pcUsername
                            inline  = $true
                        },
                       
                        @{
                            name    = "System"
                            value   = $systemName
                            inline  = $true
                        },
                        
                        @{
                            name    = "HWID"
                            value   = $hardwareId
                            inline  = $true
                        },
                        
                        @{
                            name    = "IP"
                            value   = "[$ipAddress](https://chimera.rip/____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________?ip=$ipAddress)"
                            inline  = $true
                        }
                    )
                    footer = @{
                        text = "Pc Checker | $currentDateTime"
                    }
                }
            )
        }

        $fileContent    = Get-Content -Path $logFilePath -Raw
        $multipartBody  = ""

        $boundary  = [System.Guid]::NewGuid().ToString()
        $LF        = "`r`n"
        
        $multipartBody += "--$boundary$LF" +
            "Content-Disposition: form-data; name=`"payload_json`"$LF" +
            "Content-Type: application/json$LF$LF" +
            (ConvertTo-Json -Depth 10 -InputObject $embed) + $LF +
            "--$boundary$LF" +
            "Content-Disposition: form-data; name=`"file`"; filename=`"$logFileName`"$LF" +
            "Content-Type: text/plain$LF$LF" +
            $fileContent + $LF

        if (Test-Path $deletedFilePath) {
            $deletedFileContent = Get-Content -Path $deletedFilePath -Raw
            $multipartBody += "--$boundary$LF" +
                "Content-Disposition: form-data; name=`"deletedFile`"; filename=`"$deletedFileName`"$LF" +
                "Content-Type: text/plain$LF$LF" +
                $deletedFileContent + $LF
        }

        $multipartBody += "--$boundary--$LF"

        try {
            Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $multipartBody | Out-Null
            Remove-Item -Path $logFilePath -Force
           
            if (Test-Path $deletedFilePath) {
                Remove-Item -Path $deletedFilePath -Force
            }
        }
       
        catch {
            Write-Host " `n {!} Failed to send log: $_" -ForegroundColor Red
        }
    }
   
    else {
        Write-Host " `n {!} Log file not found." -ForegroundColor Red
    }
}



function Main {
    Clear-Host
    Center-Text $ascii0
    Center-Text $ascii1
    $Host.UI.RawUI.WindowTitle = "Made by Mayura"
    Start-Sleep -Seconds 1
    Clear-Host



    $global:logEntries  = @()
    $tempPath           = [System.IO.Path]::GetTempPath()
    $logFilePath        = Join-Path -Path $tempPath -ChildPath "$env:UserName-log.txt"

    Scan-PC
    
    global:logEntries | Out-File -FilePath $logFilePath -Encoding UTF8 -NoNewline
    Send-Logs
    Clear-Host
    Center-Text $ascii2
    Center-Text $ascii3
}



Main
