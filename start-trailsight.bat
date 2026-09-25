@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 src\trailsight\launcher.py
    goto :eof
)
where python >nul 2>&1
if %errorlevel%==0 (
    python src\trailsight\launcher.py
    goto :eof
)
echo.
echo TrailSight needs Python, which is not installed.
echo Get it from https://www.python.org/downloads/ then double-click this again.
echo.
pause
