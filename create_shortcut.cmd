@echo off
cd /d "%~dp0"
echo [NetGuard] Dang tao shortcut tren Desktop (Run as Administrator)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0create_shortcut.ps1"
echo.
pause
