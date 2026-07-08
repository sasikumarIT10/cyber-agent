@echo off
REM ================================================================
REM  Cybersecurity AI Agent — Auto-Start Setup
REM  Works in BOTH Admin and Non-Admin sessions:
REM    Admin    -> ONSTART task (runs before any user logs in)
REM    Non-Admin-> ONLOGON task (runs when current user logs in)
REM ================================================================

echo.
echo  ======================================================
echo   Cybersecurity AI Agent — Auto-Start Installer
echo  ======================================================
echo.

REM Get the directory where this script lives
set "AGENT_DIR=%~dp0"
set "AGENT_DIR=%AGENT_DIR:~0,-1%"

REM Check Python is available
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Python not found in PATH.
    echo  Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

REM Create data directory if needed
if not exist "%AGENT_DIR%\data" mkdir "%AGENT_DIR%\data"

REM Create the wrapper script that Task Scheduler will run
echo Creating agent launcher script...
(
echo @echo off
echo REM Auto-generated launcher for Cybersecurity AI Agent
echo cd /d "%AGENT_DIR%"
echo.
echo REM Check if agent is already running on the configured port
echo netstat -ano 2^>nul ^| findstr "LISTENING" ^| findstr ":8000 " ^>nul 2^>^&1
echo if %%ERRORLEVEL%% EQU 0 (
echo     echo [%%date%% %%time%%] Agent already running on port 8000, skipping. ^>^> "%AGENT_DIR%\data\startup.log"
echo     exit /b 0
echo ^)
echo.
echo echo [%%date%% %%time%%] Agent starting... ^>^> "%AGENT_DIR%\data\startup.log"
echo python api.py 2^>^>"%AGENT_DIR%\data\startup.log"
echo echo [%%date%% %%time%%] Agent stopped ^(exit code: %%ERRORLEVEL%%^) ^>^> "%AGENT_DIR%\data\startup.log"
) > "%AGENT_DIR%\run_agent.bat"
echo   Created: %AGENT_DIR%\run_agent.bat

REM Detect admin privileges
net session >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    goto :ADMIN_SETUP
) else (
    goto :USER_SETUP
)

REM ===================== ADMIN MODE =====================
:ADMIN_SETUP
echo.
echo  [DETECTED] Running as Administrator
echo  Installing SYSTEM-LEVEL auto-start (runs on boot, before login)...
echo.

REM Remove any existing tasks (both types)
schtasks /Delete /TN "CyberSecAgent_AutoStart" /F >nul 2>&1
schtasks /Delete /TN "CyberSecAgent_UserStart" /F >nul 2>&1

REM Create ONSTART task — runs at boot with HIGHEST privileges
schtasks /Create ^
    /TN "CyberSecAgent_AutoStart" ^
    /TR "\"%AGENT_DIR%\run_agent.bat\"" ^
    /SC ONSTART ^
    /DELAY 0000:30 ^
    /RL HIGHEST ^
    /F

if %ERRORLEVEL% EQU 0 (
    echo  [SUCCESS] System-level auto-start registered!
    echo.
    echo  Task Name:    CyberSecAgent_AutoStart
    echo  Trigger:      On system startup (30s delay, before login)
    echo  Privilege:    HIGHEST (runs as SYSTEM)
    echo  Port Conflict: Auto-detected — skips if already running
    echo  Logs:         %AGENT_DIR%\data\startup.log
    echo.
    echo  The agent will start automatically on every boot,
    echo  even before any user logs in.
) else (
    echo  [ERROR] Failed to create system-level task.
)

REM Also create ONLOGON task as backup (in case SYSTEM task fails)
schtasks /Create ^
    /TN "CyberSecAgent_UserStart" ^
    /TR "\"%AGENT_DIR%\run_agent.bat\"" ^
    /SC ONLOGON ^
    /DELAY 0000:10 ^
    /RL LIMITED ^
    /F >nul 2>&1

if %ERRORLEVEL% EQU 0 (
    echo  [BONUS] User-login backup task also registered.
    echo          Task: CyberSecAgent_UserStart (runs on login if boot task missed)
)

echo.
echo  To remove both: auto_start_remove.bat (run as Admin)
goto :DONE

REM ===================== NON-ADMIN MODE =====================
:USER_SETUP
echo.
echo  [DETECTED] Running as Standard User (no admin privileges)
echo  Installing USER-LEVEL auto-start (runs when you log in)...
echo.

REM Remove existing user task if present
schtasks /Delete /TN "CyberSecAgent_UserStart" /F >nul 2>&1

REM Create ONLOGON task — runs when THIS user logs in, LIMITED privilege
schtasks /Create ^
    /TN "CyberSecAgent_UserStart" ^
    /TR "\"%AGENT_DIR%\run_agent.bat\"" ^
    /SC ONLOGON ^
    /DELAY 0000:15 ^
    /RL LIMITED ^
    /F

if %ERRORLEVEL% EQU 0 (
    echo  [SUCCESS] User-level auto-start registered!
    echo.
    echo  Task Name:    CyberSecAgent_UserStart
    echo  Trigger:      On user login (15s delay)
    echo  Privilege:    LIMITED (runs as current user)
    echo  Port Conflict: Auto-detected — skips if already running
    echo  Logs:         %AGENT_DIR%\data\startup.log
    echo.
    echo  The agent will start automatically when you log in.
    echo.
    echo  TIP: For boot-level auto-start (before login), re-run
    echo       this script as Administrator.
) else (
    echo  [ERROR] Failed to create user-level task.
    echo.
    echo  Alternative: Add a shortcut to run_agent.bat in your
    echo  Startup folder:
    echo    %%APPDATA%%\Microsoft\Windows\Start Menu\Programs\Startup
)

echo.
echo  To remove: auto_start_remove.bat
goto :DONE

:DONE
echo.
pause
