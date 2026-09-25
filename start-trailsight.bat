@echo off
cd /d "%~dp0"

set "TRAILSIGHT_PYTHON="
call :try py -3
call :try python
if not defined TRAILSIGHT_PYTHON for /f "tokens=2,*" %%A in ('reg query "HKCU\Software\Python\PythonCore" /s /v ExecutablePath 2^>nul ^| findstr /i "ExecutablePath"') do call :try "%%B"
if not defined TRAILSIGHT_PYTHON for /f "tokens=2,*" %%A in ('reg query "HKLM\Software\Python\PythonCore" /s /v ExecutablePath 2^>nul ^| findstr /i "ExecutablePath"') do call :try "%%B"
if not defined TRAILSIGHT_PYTHON goto :missing

%TRAILSIGHT_PYTHON% src\trailsight\launcher.py
goto :eof

:try
if defined TRAILSIGHT_PYTHON goto :eof
%* -c "import sys; raise SystemExit(sys.version_info[:2] < (3, 12))" >nul 2>&1
if errorlevel 1 goto :eof
set "TRAILSIGHT_PYTHON=%*"
goto :eof

:missing
echo.
echo TrailSight could not find Python 3.12 or newer.
echo Get it from https://www.python.org/downloads/ then double-click this again.
echo.
pause
