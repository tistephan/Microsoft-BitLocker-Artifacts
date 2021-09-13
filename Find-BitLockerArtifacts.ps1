<#
    .SYNOPSIS
        Durchsucht Windows 10-Installationen nach Hinweisen zur Nutzung von Microsoft BitLocker.

    .DESCRIPTION
        Erkennungsmerkmale von Microsoft BitLocker sind in zwei Konfigurationsdateien im JSON-Format gespeichert.
        
        Systemanforderungen:
            Microsoft PowerShell
                - Version 7.1.3 unter Microsoft Windows oder Linux installiert
                - ExecutionPolicy = Unrestricted oder durch die Kommandozeile mit pswh.exe umgehen (siehe Abschnitt Example)
            
            Ausführung:
                Skript als Administrator bzw. root ausführen, um Zugriff auf alle standardmäßigen Dateien zu erhalten
                Jeweils eine Datei mit Merkmalen zur Identifizierung von Artefakten (Artifacts.json) und Regel (Rules.json)

            Untersuchung:
                - Eine Microsoft Windows 10-Installation zur Untersuchung, entweder als "Live-System"
                - Alternativ: Windows 10-Verzeichnisse schreibgeschützt bereitstellen (z. B. EWF-Datei)

    .EXAMPLE
        Find-BitLockerArtifacts.ps1 <Laufwerk>:\Windows .\Rules.json .\Artifacts.json
        pwsh.exe -ExecutionPolicy Bypass -File Find-BitLockerArtifacts.ps1 <Laufwerk>:\Windows .\Rules.json .\Artifacts.json

    .LINK
        https://github.com/tistephan/Microsoft-BitLocker-Artifacts
#>

Param(
    #[Parameter(Mandatory=$true)]
    [string]$windows_directory, # Das Verzeichnis mit der Windows-Installation
    [string]$rules_file,         # Datei mit den Regeln
    [string]$artifacts_file      # Datei mit den Artefakten
)

if ($windows_directory -eq "" -or $rules_file -eq "" -or $artifacts_file -eq "") {
    $host.UI.WriteErrorLine("    Missing Parameter(s)!")
    $host.UI.WriteErrorLine("    Start with: .\Find-BitLockerArtifacts.ps1 -windows_directory ""<DriveLetter>:\Windows"" -rules_file ""Rules-Data.json"" -artifacts_file ""Artifacts-Data.json"" ")
    exit
}

Clear-Host

$returnValue = [System.Collections.ArrayList]::new()

# JSON-Dateien einlesen
$rules = @(Get-Content -Encoding UTF8 "$($rules_file)") | ConvertFrom-Json
$artifacts = @(Get-Content -Encoding UTF8 "$($artifacts_file)") | ConvertFrom-Json

# JSON-Dateien in ArrayList konvertieren
$array_rules = [System.Collections.ArrayList]::new()
$array_artifacts = [System.Collections.ArrayList]::new()
foreach ($r in $rules) { $array_rules += ,@($r) }
foreach ($a in $artifacts) { $array_artifacts += ,@($a) }

if ($isWindows -eq $true) {
    if (($windows_directory.ToLower() -eq $env:windir.ToLower())) {
        $live_analysis = $true
    } else {
        $live_analysis = $false
    }
}

foreach ($r in $array_rules) {
    $returnValue += ,@("-------------------","Regel ""$($r.title)"" gestartet -------------------","","","","")
    foreach ($ra in $r.artifact) {
        foreach ($a in $array_artifacts) {     
            if ($ra -eq $a.title) {  
                if ($a.type -eq "File") {
                    if ($a.path -ne "") {
                        $path = $a.path
                    } else {
                        # Keine Pfadangabe = gesamtes Betriebssystemlaufwerk der Windows-Installation durchsuchen
                        if ($isWindows) {
                            $path = "$($windows_directory.Substring(0,1)):\"
                        } else {
                            $path=$a.path
                        }
                    }

                    if ($path.Contains('Prefetch')) {
                        $returnCode = Get-ChildItem "$($path)\$($a.value)" | Measure-Object | Select-Object -ExpandProperty Count
                        $returnValue += ,@($timestamp,$a.type,$a.title,"$($a.value) = $($returnCode)") # Ergebnis in ArrayList speichern: Timestamp, Rule-Title, Artefakt-Titel, Rückgabewert

                    } elseif ($a.value -eq "ConsoleHost_history.txt") {
                        $returnCode = Get-ChildItem "$($path)\$($a.value)" | Measure-Object | Select-Object -ExpandProperty Count
                        $returnValue += ,@($timestamp,$a.type,$a.title,"$($a.value) = $($returnCode)")
                    } else {
                        # BitLocker-Wiederherstellungsschlüssel suchen
                        $files=Get-ChildItem -Path "$($path)" -Recurse -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.FullName -match "BitLocker-Wiederherstellungsschlüssel [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" } | Select-Object -ExpandProperty FullName

                        foreach ($f in $files) {
                            [string]$textfile = Get-Content $f -Encoding "windows-1251"
    
                            $pattern_begin = $textfile.IndexOf($a.'pattern begin')
                            if ($pattern_begin -ne -1) {
                                $pattern_end = $textfile.IndexOf($a.'pattern end', $pattern_begin)
                            } else {
                                $pattern_end = -1
                            }
    
                            if ($pattern_begin -lt $pattern_end -and $pattern_begin -ne -1 -and $pattern_end -ne -1) {          
                                $pattern_result=$textfile.Substring(($pattern_begin+$a.'pattern begin'.Length),($pattern_end-$pattern_begin-$a.'pattern begin'.Length))
                                $pattern_result=$pattern_result.Replace("`r","")
                                $pattern_result=$pattern_result.Replace("`n","")
                                $pattern_result=$pattern_result.Trim()
                                $timestamp = Get-Item $f | Select-Object -ExpandProperty LastWriteTime | Get-Date -f "dd.MM.yyyy HH:mm:ss"
                            }
                        }
                        # Ergebnis in ArrayList speichern: Timestamp, Rule-Title, Artefakt-Titel, Rückgabewert
                        $returnValue += ,@($timestamp,$a.type,$a.title,"$($f) = $($pattern_result)")
                    }
                } elseif ($a.type -eq "Event Log") {
                    if ($IsLinux) {
                        # Ereigniseinträge sind unter Linux durch PowerShell nicht auszuwerten
                        $returnValue += ,@((Get-Date -f "dd.MM.yyyy HH:mm:ss"),$a.type,$a.title,"Keine Auswertung möglich, da unter Linux nicht unterstützt.","")
                        break
                    }

                    # Dateinamenkonvention korrigieren
                    $filename = $a.path.Replace("/","%4")
                    $pattern_begin=$pattern_end=$pattern_result=""

                    if (Test-Path("$($windows_directory)\System32\winevt\Logs\$($filename).evtx") -ErrorAction SilentlyContinue) {
                        $evtx_tempfile = "Temp_$(Get-Date -Format "yyyyMMdd_HHmmss").evtx"
                        Copy-Item "$($windows_directory)\System32\winevt\Logs\$($filename).evtx" $evtx_tempfile # Get-WinEvent benötigt Schreibzugriff, daher mit Kopie arbeiten
                        
                        if ($a.value -eq "") {
                            # Log nach String "-BitLocker" durchsuchen 
                            $returnCode = Get-WinEvent -Path $evtx_tempfile -ErrorAction SilentlyContinue | Where-Object { $_.Message -like '*-BitLocker*' } | Measure-Object  | Select-Object -ExpandProperty Count
                            $timestamp = ""
                        } else {
                            # Nach Event-ID abfragen
                            if ($a.'pattern begin' -eq "") {
                                $tempObject = Get-WinEvent -Path $evtx_tempfile -ErrorAction SilentlyContinue | Where-Object { $a.value -eq $a.value }
                            } else {
                                $tempObject = Get-WinEvent -Path $evtx_tempfile -ErrorAction SilentlyContinue | Where-Object { $a.value -eq $a.value -and $_.Message -like "*$($a.'pattern begin')*" -and $_.Message -like "*$($a.'pattern end')*" }
                            }

                            if ($returnCode -gt 0) {
                                foreach ($t in $tempObject) {
                                    $pattern_begin = $t.Message.ToString().IndexOf($a.'pattern begin')
                                    if ($pattern_begin -ne -1) {
                                        $pattern_end = $t.Message.ToString().IndexOf($a.'pattern end', $pattern_begin)
                                    } else {
                                        $pattern_end = -1
                                    }

                                    if ($pattern_begin -lt $pattern_end -and $pattern_begin -ne -1 -and $pattern_end -ne -1) {                            
                                        $pattern_result=$t.Message.ToString().Substring(($pattern_begin+$a.'pattern begin'.ToString().Length),($pattern_end-$pattern_begin-$a.'pattern begin'.ToString().Length))
                                        $pattern_result=$pattern_result.Replace("`r","")
                                        $pattern_result=$pattern_result.Replace("`n","")
                                        $pattern_result=$pattern_result.Trim()

                                        # Datumformat angleichen
                                        $timestamp = $t.TimeCreated -replace "/", "\."
                                    }
                                }
                            }       
                        }    
                        $returnValue += ,@($timestamp,$a.type,$a.title,$pattern_result,$returnCode)
                        Remove-Item "$($evtx_tempfile)" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue   # Datei-Kopie wieder entfernen
                    }
                } elseif ($a.type -eq "Registry") {
                    if ($IsLinux) {
                        $returnValue += ,@((Get-Date -f "dd.MM.yyyy HH:mm:ss"),$a.type,$a.title,"Keine Auswertung möglich, da unter Linux nicht unterstützt.","")
                        break
                    }
                    
                    if ($live_analysis -eq $true) {
                        # Windows-Registrierungsdatenbank von Live-System abfragen
                        $registry_path = $a.path
                    } else {
                        # Windows-Registrierungsdatenbank eines Offline-Systems abfragen
                        if ($a.path.ToLower().startswith("hklm:\system")) {
                            $registry_path = $a.path -replace "HKLM:\\SYSTEM","HKLM:\OfflineSystem"
                            $registry_path = $registry_path -replace "\\CurrentControlSet\\","\ControlSet001\"     # Offline: Registrierungsschlüssel "CurrentControlSet" existiert nicht
                            Start-Process "reg.exe" -ArgumentList "load ""HKLM\OfflineSystem"" ""$($windows_directory)\System32\config\system"""
                        }
                        if ($a.path.ToLower().startswith("hklm:\software")) {
                            $registry_path = $a.path -replace "HKLM:\\SOFTWARE","HKLM:\OfflineSoftware"
                            $registry_path = $registry_path -replace "\\CurrentControlSet\\","\ControlSet001\"     # Offline: Registrierungsschlüssel "CurrentControlSet" existiert nicht
                            Start-Process "reg.exe" -ArgumentList "load ""HKLM\OfflineSoftware"" ""$($windows_directory)\System32\config\software"""
                        }
                    }
                    $registry_value = (Get-ItemProperty -Path "$($registry_path)" -Name "$($a.value)" -ErrorAction SilentlyContinue).Psobject.Properties | Where-Object { $_.Name -cnotlike 'PS*' } | Select-Object -ExpandProperty Value

                    if ($registry_value.length -eq 0) {
                        $returnCode = 0
                    } else {
                        $returnCode = 1
                    }

                    if ($live_analysis -eq $false) {
                        Start-Process "reg.exe" -ArgumentList "unload ""HKLM\OfflineSystem""" 
                        Start-Process "reg.exe" -ArgumentList "unload ""HKLM\OfflineSoftware""" 
                    }
                    $returnValue += ,@("",$a.type,$a.title,$($registry_value),$returnCode,$r.artifact.Item(2))
                }
            }
        }
    }
    $returnValue += ,@("-------------------","Regel ""$($r.title)"" beendet -------------------","","","","")
    $returnValue += ,@("","","","","","")
}

Write-Host ""
Write-Host "REPORT - Find-BitLockerArtifacts.ps1"
Write-Host ""
Write-Host "Angaben zur untersuchten Windows-Installation:"
Write-Host "  Speicherort: $($windows_directory)"
if ($live_analysis -eq $true) {
    Write-Host "  Analyse: Live-System"
} else {
    Write-Host "  Analyse: Offline-Datenträger."
}
Write-Host "  Vewendetes Benutzerkonto: $($env:USERDOMAIN)\$($env:USERNAME)"

Write-Host ""
Write-Host "Artefakte:"
foreach ($p in $returnValue) {
    if ($p.Contains("-------------------")) {
        Write-Host "$($p[0]) $($p[1])"
    } else {
        if ($p[0].length -eq 0) {
            Write-Host -NoNewline "                   "
        } else {
            Write-Host -NoNewline $($p[0])
        }
        if ($p[3].length -gt 50) {
            Write-Host " $($p[2])="
            Write-Host "                    $($p[3].Substring(0,50))..."
        } else {
            if ($p[2] -ne "" ) {
                Write-Host " $($p[2])=$($p[3])"
            } else {
                Write-Host ""
            }
        }
    }
}
Write-Host "Hinweis:"
Write-Host " - Zeitstempel von Dateien entsprechen dem Änderungsdatum!"