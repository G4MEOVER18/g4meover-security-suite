#Requires -RunAsAdministrator
<#
.SYNOPSIS
    G4MEOVER Security Suite – Windows Defender Ausnahmen
.DESCRIPTION
    Fügt alle Pentest-Tool-Verzeichnisse zu den Windows Defender Ausnahmen hinzu,
    damit die Tools nicht gelöscht oder blockiert werden.
    Muss als Administrator ausgeführt werden.
#>

$ErrorActionPreference = "Stop"

# ── Farb-Ausgabe ──────────────────────────────────────────────────────────────
function Write-OK   { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green  }
function Write-SKIP { param($msg) Write-Host "  [--]  $msg" -ForegroundColor Yellow }
function Write-ERR  { param($msg) Write-Host "  [!!]  $msg" -ForegroundColor Red    }
function Write-INFO { param($msg) Write-Host "  [*]   $msg" -ForegroundColor Cyan   }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║    G4MEOVER Security Suite – Defender-Ausnahmen einrichten  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Verzeichnisse & Pfade ────────────────────────────────────────────────────
$ExcludePaths = @(
    # Haupt-Tools-Verzeichnis (alle Pentest-Tools)
    "C:\tools",

    # Metasploit Framework
    "C:\metasploit-framework",

    # ExploitDB (searchsploit)
    "C:\tools\exploitdb",

    # Hashcat
    "C:\tools\Pentesting",
    "C:\tools\Pentesting\hashcat-6.2.6 (1)",

    # gobuster / feroxbuster
    "C:\tools\gobuster",
    "C:\tools\feroxbuster",

    # Hydra
    "C:\tools\hydra",

    # John the Ripper
    "C:\tools\john",

    # Masscan
    "C:\tools\masscan",

    # nikto
    "C:\tools\nikto",

    # whatweb
    "C:\tools\whatweb",

    # OpenClaw / G4MEOVER Suite
    "C:\Data\KI\apps\openclaw",

    # Python-Scripts (sqlmap, etc.)
    "$env:LOCALAPPDATA\Programs\Python\Python312\Scripts",
    "$env:LOCALAPPDATA\Programs\Python\Python312\Lib\site-packages",

    # Nmap (normalerweise kein Problem, aber sicher ist sicher)
    "C:\Program Files (x86)\Nmap",
    "C:\Program Files\Nmap",

    # Wireshark / tshark
    "C:\Program Files\Wireshark",

    # Wordlisten und Workspace
    "C:\wordlists",
    "C:\Users\Yanis\pentest",
)

# ── Prozesse ausschließen ─────────────────────────────────────────────────────
$ExcludeProcesses = @(
    "hashcat.exe",
    "gobuster.exe",
    "feroxbuster.exe",
    "masscan.exe",
    "nmap.exe",
    "tshark.exe",
    "dumpcap.exe",
    "john.exe",
    "ruby.exe",        # nikto / whatweb
    "perl.exe",        # nikto
    "msfconsole.bat",
)

# ── Dateierweiterungen ausschließen ──────────────────────────────────────────
$ExcludeExtensions = @(
    ".cap",
    ".pcap",
    ".pcapng",
    ".hc22000",
    ".hccapx",
    ".hash",
    ".potfile",
    ".rule",
    ".dict",
    ".wordlist",
)

# ── Aktuelle Ausnahmen lesen ─────────────────────────────────────────────────
Write-Info "Lese aktuelle Defender-Konfiguration..."
try {
    $pref = Get-MpPreference
    $existingPaths = $pref.ExclusionPath   ?? @()
    $existingProcs = $pref.ExclusionProcess ?? @()
    $existingExts  = $pref.ExclusionExtension ?? @()
    Write-OK "Defender-Konfiguration gelesen ($($existingPaths.Count) bestehende Pfad-Ausnahmen)"
} catch {
    Write-ERR "Konnte Defender-Konfiguration nicht lesen: $_"
    exit 1
}

# ── Pfade hinzufügen ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Pfad-Ausnahmen ─────────────────────────────────────────────" -ForegroundColor Cyan
$addedPaths = 0
foreach ($path in $ExcludePaths) {
    # Umgebungsvariablen auflösen
    $resolved = [System.Environment]::ExpandEnvironmentVariables($path)

    if ($existingPaths -contains $resolved) {
        Write-SKIP "Bereits vorhanden: $resolved"
        continue
    }

    try {
        Add-MpPreference -ExclusionPath $resolved
        Write-OK "Hinzugefügt: $resolved"
        $addedPaths++
    } catch {
        Write-ERR "Fehler bei '$resolved': $_"
    }
}

# ── Prozesse hinzufügen ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Prozess-Ausnahmen ──────────────────────────────────────────" -ForegroundColor Cyan
$addedProcs = 0
foreach ($proc in $ExcludeProcesses) {
    if ($existingProcs -contains $proc) {
        Write-SKIP "Bereits vorhanden: $proc"
        continue
    }
    try {
        Add-MpPreference -ExclusionProcess $proc
        Write-OK "Hinzugefügt: $proc"
        $addedProcs++
    } catch {
        Write-ERR "Fehler bei '$proc': $_"
    }
}

# ── Erweiterungen hinzufügen ──────────────────────────────────────────────────
Write-Host ""
Write-Host "── Dateiendungs-Ausnahmen ─────────────────────────────────────" -ForegroundColor Cyan
$addedExts = 0
foreach ($ext in $ExcludeExtensions) {
    if ($existingExts -contains $ext) {
        Write-SKIP "Bereits vorhanden: $ext"
        continue
    }
    try {
        Add-MpPreference -ExclusionExtension $ext
        Write-OK "Hinzugefügt: $ext"
        $addedExts++
    } catch {
        Write-ERR "Fehler bei '$ext': $_"
    }
}

# ── Zusammenfassung ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Fertig! Zusammenfassung:" -ForegroundColor Green
Write-Host "║   Pfade hinzugefügt:      $($addedPaths.ToString().PadLeft(3))" -ForegroundColor Green
Write-Host "║   Prozesse hinzugefügt:   $($addedProcs.ToString().PadLeft(3))" -ForegroundColor Green
Write-Host "║   Erweiterungen:          $($addedExts.ToString().PadLeft(3))" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# ── Aktuellen Status anzeigen ─────────────────────────────────────────────────
Write-Host "── Aktuelle Ausnahmen (Pfade) ─────────────────────────────────" -ForegroundColor Cyan
$pref2 = Get-MpPreference
foreach ($p in ($pref2.ExclusionPath | Sort-Object)) {
    Write-Host "   $p" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Hinweis: Starte Windows Defender neu oder reboote wenn Tools weiterhin blockiert werden." -ForegroundColor Yellow
Write-Host "         Einige Änderungen werden erst nach einem Neustart des Defender-Dienstes aktiv." -ForegroundColor Yellow
Write-Host ""
