@echo off
setlocal EnableDelayedExpansion
title Cybersecurity AI Agent - One-Click Setup
color 0B

echo.
echo  ============================================================
echo        Cybersecurity AI Agent - One-Click Automated Setup
echo  ============================================================
echo.
echo  This script will:
echo    [1] Check Python installation
echo    [2] Create virtual environment
echo    [3] Install all dependencies
echo    [4] Configure API keys (.env)
echo    [5] Verify everything works
echo    [6] Register auto-start (optional)
echo    [7] Launch the agent
echo.
echo  ============================================================
echo.
pause

REM Get script directory
set "AGENT_DIR=%~dp0"
set "AGENT_DIR=%AGENT_DIR:~0,-1%"
cd /d "%AGENT_DIR%"

REM ===================== STEP 1: Python Check =====================
echo.
echo  [1/7] Checking Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Python is NOT installed or not in PATH.
    echo.
    echo  Please install Python 3.10+ from:
    echo    https://www.python.org/downloads/
    echo.
    echo  IMPORTANT: Check "Add Python to PATH" during installation.
    echo  Then re-run this script.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found.

REM Check Python version is 3.10+
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if %PY_MAJOR% LSS 3 (
    echo  [ERROR] Python 3.10+ is required. Found %PYVER%.
    pause
    exit /b 1
)
if %PY_MAJOR% EQU 3 if %PY_MINOR% LSS 10 (
    echo  [ERROR] Python 3.10+ is required. Found %PYVER%.
    pause
    exit /b 1
)

REM ===================== STEP 2: Virtual Environment =====================
echo.
echo  [2/7] Setting up virtual environment...
if not exist "venv" (
    echo  Creating venv...
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
) else (
    echo  [OK] Virtual environment already exists.
)

call venv\Scripts\activate.bat

REM ===================== STEP 3: Install Dependencies =====================
echo.
echo  [3/7] Installing dependencies (this may take a few minutes)...
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Dependency installation failed.
    echo  Check your internet connection and try again.
    pause
    exit /b 1
)
echo  [OK] All dependencies installed.

REM ===================== STEP 4: API Key Configuration =====================
echo.
echo  [4/7] Configuring API keys...

REM Check if .env already has a real API key
set "HAS_KEY=0"
if exist ".env" (
    for /f "tokens=1,* delims==" %%a in ('findstr /i "ANTHROPIC_API_KEY" .env 2^>nul') do (
        set "EXISTING_KEY=%%b"
        if not "!EXISTING_KEY!"=="" (
            if not "!EXISTING_KEY!"=="your-anthropic-api-key-here" (
                set "HAS_KEY=1"
                echo  [OK] Anthropic API key already configured.
            )
        )
    )
)

if "!HAS_KEY!"=="0" (
    echo.
    echo  ============================================================
    echo   You need an Anthropic API key to run this agent.
    echo.
    echo   Get your key from: https://console.anthropic.com/
    echo     1. Sign up / Log in
    echo     2. Go to API Keys
    echo     3. Click "Create Key"
    echo     4. Copy the key (starts with sk-ant-)
    echo  ============================================================
    echo.
    set /p "API_KEY=  Paste your Anthropic API key here: "

    if "!API_KEY!"=="" (
        echo  [ERROR] No API key entered. Cannot continue.
        pause
        exit /b 1
    )

    REM Validate key format
    echo !API_KEY! | findstr /b "sk-ant-" >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo.
        echo  [WARNING] Key doesn't start with "sk-ant-". It may not be valid.
        set /p "CONTINUE=  Continue anyway? (Y/N): "
        if /i not "!CONTINUE!"=="Y" (
            echo  Setup cancelled.
            pause
            exit /b 1
        )
    )

    REM Create .env from template if needed
    if not exist ".env" (
        copy .env.example .env >nul
    )

    REM Write the API key into .env
    powershell -Command "(Get-Content '.env') -replace 'ANTHROPIC_API_KEY=.*', 'ANTHROPIC_API_KEY=!API_KEY!' | Set-Content '.env'"
    echo  [OK] API key saved to .env

    REM Ask for optional keys
    echo.
    echo  Optional API keys (press Enter to skip each):
    echo.
    set /p "VT_KEY=  VirusTotal API key (for malware hash checks): "
    if not "!VT_KEY!"=="" (
        powershell -Command "(Get-Content '.env') -replace 'VIRUSTOTAL_API_KEY=.*', 'VIRUSTOTAL_API_KEY=!VT_KEY!' | Set-Content '.env'"
        echo  [OK] VirusTotal key saved.
    )

    set /p "ABUSE_KEY=  AbuseIPDB API key (for IP reputation): "
    if not "!ABUSE_KEY!"=="" (
        powershell -Command "(Get-Content '.env') -replace 'ABUSEIPDB_API_KEY=.*', 'ABUSEIPDB_API_KEY=!ABUSE_KEY!' | Set-Content '.env'"
        echo  [OK] AbuseIPDB key saved.
    )

    set /p "SHODAN_KEY=  Shodan API key (for internet scanning): "
    if not "!SHODAN_KEY!"=="" (
        powershell -Command "(Get-Content '.env') -replace 'SHODAN_API_KEY=.*', 'SHODAN_API_KEY=!SHODAN_KEY!' | Set-Content '.env'"
        echo  [OK] Shodan key saved.
    )
)

REM ===================== STEP 5: Verify Setup =====================
echo.
echo  [5/7] Verifying setup...

REM Create data directory
if not exist "data" mkdir data

REM Test Python imports
python -c "import langchain_anthropic; import langgraph; import fastapi; import httpx; print('OK')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] Some Python packages failed to import.
    echo  Try running: pip install -r requirements.txt
    pause
    exit /b 1
)
echo  [OK] All Python packages verified.

REM Test config loads
python -c "import config; print(f'  Model: {config.AGENT_MODEL}'); print(f'  Port: {config.API_PORT}'); print(f'  API Key: {config.ANTHROPIC_API_KEY[:10]}...' if len(config.ANTHROPIC_API_KEY) > 10 else '  API Key: (not set)')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo  [WARNING] Config load had issues, but may still work.
)

REM Test API key validity with a minimal request
echo  Validating API key...
python -c "import httpx; r = httpx.post('https://api.anthropic.com/v1/messages', headers={'x-api-key': open('.env').read().split('ANTHROPIC_API_KEY=')[1].split('\n')[0].strip(), 'anthropic-version': '2023-06-01', 'content-type': 'application/json'}, json={'model': 'claude-sonnet-4-20250514', 'max_tokens': 10, 'messages': [{'role': 'user', 'content': 'hi'}]}); print('  [OK] API key is valid!' if r.status_code == 200 else f'  [WARNING] API returned status {r.status_code}. Key may be invalid or rate-limited.')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo  [WARNING] Could not validate API key (network issue?). Continuing...
)

REM ===================== STEP 6: Auto-Start (Optional) =====================
echo.
echo  [6/7] Auto-start configuration...
echo.
set /p "AUTOSTART=  Register agent to start automatically on boot? (Y/N): "
if /i "!AUTOSTART!"=="Y" (
    echo.
    echo  Running auto-start installer...
    call auto_start_setup.bat
) else (
    echo  [SKIPPED] Auto-start not registered.
    echo  You can run auto_start_setup.bat later if you change your mind.
)

REM ===================== STEP 7: Launch Agent =====================
echo.
echo  ============================================================
echo   Setup Complete! Your agent is ready.
echo  ============================================================
echo.
echo  How do you want to launch the agent?
echo.
echo    [1] Web UI  (browser-based dashboard)
echo    [2] CLI     (terminal chat)
echo    [3] Exit    (launch later manually)
echo.
set /p "LAUNCH=  Choose (1/2/3): "

if "!LAUNCH!"=="1" (
    echo.
    echo  Starting Web UI... Opening browser in 3 seconds.
    start "" cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:8000"
    python api.py
) else if "!LAUNCH!"=="2" (
    echo.
    echo  Starting CLI agent...
    python cli.py
) else (
    echo.
    echo  To launch later, use:
    echo    start-web.bat    - Web UI + API
    echo    start-cli.bat    - Terminal chat
    echo    test-tools.bat   - Quick tool tests
)

echo.
pause
