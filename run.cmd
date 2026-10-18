@echo off
setlocal

:: Chuyen ve thu muc goc chua script
cd /d "%~dp0"

:: Kiem tra tham so dac biet
if /i "%~1"=="--help" goto :help
if /i "%~1"=="-h" goto :help
if /i "%~1"=="/?" goto :help
if /i "%~1"=="--vbs" goto :run_vbs
if /i "%~1"=="-s" goto :run_vbs
if /i "%~1"=="--silent" goto :run_vbs
if /i "%~1"=="--admin" goto :run_admin
if /i "%~1"=="-a" goto :run_admin
if /i "%~1"=="--shortcut" goto :create_shortcut

:: Xac dinh Python trong moi truong ao (.venv)
set "PY_EXE=%~dp0.venv\Scripts\python.exe"
set "PYW_EXE=%~dp0.venv\Scripts\pythonw.exe"

if not exist "%PY_EXE%" (
    echo [NetGuard] Khong tim thay moi truong ao tai .venv
    where uv >nul 2>&1
    if %errorlevel% equ 0 (
        echo [NetGuard] Dang chay bang 'uv run'...
        uv run netguard %*
        exit /b %errorlevel%
    ) else (
        echo [NetGuard] Vui long cai dat moi truong truoc: uv sync
        pause
        exit /b 1
    )
)

:: Chay voi console neu muon xem log hoac test
if /i "%~1"=="--console" (
    shift
    "%PY_EXE%" -m netguard %*
    exit /b %errorlevel%
)
if /i "%~1"=="-c" (
    shift
    "%PY_EXE%" -m netguard %*
    exit /b %errorlevel%
)
if /i "%~1"=="--etw-test" (
    "%PY_EXE%" -m netguard %*
    exit /b %errorlevel%
)

:: Mac dinh chay che do GUI ngam (khong luu cua so CMD)
if exist "%PYW_EXE%" (
    start "" "%PYW_EXE%" -m netguard %*
) else (
    start "" "%PY_EXE%" -m netguard %*
)
exit /b 0

:run_vbs
shift
if exist "%~dp0run.vbs" (
    wscript.exe "%~dp0run.vbs" %*
) else (
    echo [NetGuard] Khong tim thay file run.vbs
)
exit /b 0

:run_admin
shift
echo [NetGuard] Dang yeu cau quyen Administrator qua UAC...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c \"\"%~dp0run.cmd\" %*\"' -Verb RunAs"
exit /b 0

:create_shortcut
shift
if exist "%~dp0create_shortcut.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0create_shortcut.ps1"
) else (
    echo [NetGuard] Khong tim thay create_shortcut.ps1
)
exit /b 0

:help
echo =========================================================
echo             NetGuard - Trinh khoi chay (run.cmd)
echo =========================================================
echo.
echo Cac lenh ho tro:
echo   run.cmd                 : Khoi chay NetGuard GUI
echo   run.cmd --console (-c)  : Chay va hien thi console de xem log
echo   run.cmd --vbs (-s)      : Chay qua run.vbs hoan toan khong nhap nhay CMD
echo   run.cmd --admin (-a)    : Chay voi quyen Administrator (UAC)
echo   run.cmd --shortcut      : Tao shortcut NetGuard ra ngoai Desktop
echo   run.cmd --etw-test      : Chay kiem tra chan doan ETW kernel
echo   run.cmd --dry-run       : Chay thu nghiem (khong tac dong Windows Firewall)
echo.
exit /b 0
