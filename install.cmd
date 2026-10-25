@echo off
REM One-click installer for allfinder on Windows.
REM Double-click this file, or run it from a terminal.
REM Pass /dev to also install the test tools, /data to download wordlists.

setlocal
cd /d "%~dp0"

set ARGS=
if /I "%~1"=="/dev"  set ARGS=%ARGS% -Dev
if /I "%~1"=="-dev"  set ARGS=%ARGS% -Dev
if /I "%~2"=="/data" set ARGS=%ARGS% -WithData
if /I "%~1"=="/data" set ARGS=%ARGS% -WithData

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" %ARGS%
set RC=%ERRORLEVEL%

echo.
if %RC%==0 (
    echo Install finished successfully.
) else (
    echo Install FAILED - see the red message above.
)
echo Press any key to close this window...
pause >nul
exit /b %RC%
