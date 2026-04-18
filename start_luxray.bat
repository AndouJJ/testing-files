@echo off
REM ============================================================================
REM Luxray + Arkime Startup Script
REM ============================================================================
REM This script starts:
REM   1. Arkime services in WSL2 (OpenSearch, Viewer, Capture)
REM   2. Luxray web application
REM
REM To run on Windows startup:
REM   1. Press Win+R, type: shell:startup
REM   2. Create a shortcut to this file in that folder
REM ============================================================================

echo ============================================
echo   Starting Luxray + Arkime Services
echo ============================================
echo.

REM Start Arkime services in WSL2
echo [1/2] Starting Arkime services in WSL2...
wsl -d Ubuntu-24.04 -u root -- bash -c "cd /opt/arkime && nohup /opt/opensearch/bin/opensearch > /var/log/opensearch.log 2>&1 & sleep 5 && nohup /opt/arkime/bin/run_viewer.sh > /var/log/arkime-viewer.log 2>&1 & nohup /opt/arkime/bin/run_capture.sh > /var/log/arkime-capture.log 2>&1 &"
echo Arkime services starting in background...
echo.

REM Wait for services to initialize
echo Waiting for services to initialize (15 seconds)...
timeout /t 15 /nobreak > nul

REM Start Luxray
echo [2/2] Starting Luxray...
cd /d d:\testing\files
start "Luxray" cmd /k "python arkime_web.py"

echo.
echo ============================================
echo   All services started!
echo ============================================
echo.
echo   Arkime Viewer: http://localhost:8005
echo   Luxray:        http://localhost:8080
echo.
echo Press any key to close this window...
pause > nul
