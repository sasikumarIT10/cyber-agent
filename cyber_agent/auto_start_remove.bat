@echo off
REM ================================================================
REM  Remove ALL auto-start tasks (both admin and non-admin)
REM ================================================================
echo.
echo  Removing Cybersecurity AI Agent auto-start tasks...
echo.

set REMOVED=0

REM Try removing system-level task
schtasks /Delete /TN "CyberSecAgent_AutoStart" /F >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  [REMOVED] CyberSecAgent_AutoStart (system-level boot task)
    set REMOVED=1
)

REM Try removing user-level task
schtasks /Delete /TN "CyberSecAgent_UserStart" /F >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  [REMOVED] CyberSecAgent_UserStart (user-level login task)
    set REMOVED=1
)

if %REMOVED% EQU 0 (
    echo  [INFO] No auto-start tasks found — nothing to remove.
    echo.
    echo  NOTE: If the system-level task exists but you're not admin,
    echo        re-run this script as Administrator to remove it.
) else (
    echo.
    echo  [DONE] Auto-start disabled. The agent will no longer start
    echo         automatically on boot or login.
)

echo.
pause
