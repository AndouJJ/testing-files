@echo off
REM ============================================================================
REM Luxray + Arkime Stop Script
REM ============================================================================

echo ============================================
echo   Stopping Luxray + Arkime Services
echo ============================================
echo.

REM Stop Luxray (Python process)
echo [1/2] Stopping Luxray...
taskkill /f /im python.exe 2>nul
if %errorlevel%==0 (echo Luxray stopped.) else (echo Luxray was not running.)
echo.

REM Stop Arkime services in WSL2
echo [2/2] Stopping Arkime services in WSL2...
wsl -d Ubuntu -u root -- bash -c "pkill -f opensearch; pkill -f viewer; pkill -f capture" 2>nul
echo Arkime services stopped.
echo.

echo ============================================
echo   All services stopped!
echo ============================================
echo.
pause
