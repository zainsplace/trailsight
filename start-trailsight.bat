@echo off
cd /d "%~dp0"

py -3 -c "" >nul 2>&1
if not errorlevel 1 (
    py -3 src\trailsight\launcher.py
    goto :eof
)

python -c "" >nul 2>&1
if not errorlevel 1 (
    python src\trailsight\launcher.py
    goto :eof
)

set "TRAILSIGHT_PYTHON="
for /f "tokens=2,*" %%A in ('reg query "HKCU\Software\Python\PythonCore" /s /v ExecutablePath 2^>nul ^| findstr /i "ExecutablePath"') do call :try "%%B"
if not defined TRAILSIGHT_PYTHON for /f "tokens=2,*" %%A in ('reg query "HKLM\Software\Python\PythonCore" /s /v ExecutablePath 2^>nul ^| findstr /i "ExecutablePath"') do call :try "%%B"
if not defined TRAILSIGHT_PYTHON goto :missing

"%TRAILSIGHT_PYTHON%" src\trailsight\launcher.py
goto :eof

:try
if defined TRAILSIGHT_PYTHON goto :eof
%1 -c "" >nul 2>&1
if errorlevel 1 goto :eof
set "TRAILSIGHT_PYTHON=%~1"
goto :eof

:missing
echo.
echo TrailSight could not find a working Python.
echo Get it from https://www.python.org/downloads/ then double-click this again.
echo.
pause
