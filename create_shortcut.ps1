# NetGuard - Script tao Desktop Shortcut voi quyen Administrator
$ErrorActionPreference = "Stop"

$appDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "NetGuard.lnk"
$exePath = Join-Path $appDir ".venv\Scripts\netguard-gui.exe"
$pywPath = Join-Path $appDir ".venv\Scripts\pythonw.exe"
$iconPath = Join-Path $appDir "assets\netguard.ico"

# Uu tien netguard-gui.exe, neu khong co thi dung pythonw.exe
$target = $exePath
$arguments = ""
if (!(Test-Path $target)) {
    $target = $pywPath
    $arguments = "-m netguard"
}

$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut($shortcutPath)
$sc.TargetPath = $target
if ($arguments) {
    $sc.Arguments = $arguments
}
$sc.WorkingDirectory = $appDir
$sc.Description = "NetGuard - Giam sat va bao ve ket noi mang Windows (Administrator)"
if (Test-Path $iconPath) {
    $sc.IconLocation = "$iconPath,0"
}
$sc.Save()

# Bat co Run as Administrator trong file .lnk (bit 6 cua byte 0x15 / 21)
$bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($shortcutPath, $bytes)

Write-Host "=========================================================" -ForegroundColor Green
Write-Host "  Da tao shortcut NetGuard (Run as Administrator)!" -ForegroundColor Green
Write-Host "  Vi tri: $shortcutPath"
Write-Host "  Target: $target $arguments"
Write-Host "  Icon  : $iconPath"
Write-Host "=========================================================" -ForegroundColor Green
