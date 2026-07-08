@echo off
title Cybersecurity AI Agent - Setup
echo.
echo  ====================================================
echo   Cybersecurity AI Agent - Windows LTSC Setup
echo  ====================================================
echo.

:: Check Python
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Windows LTSC does not have Microsoft Store, so install Python manually:
    echo.
    echo    1. Download Python 3.11+ from https://www.python.org/downloads/
    echo    2. Run the installer
    echo    3. IMPORTANT: Check "Add Python to PATH" during install
    echo    4. Restart this script after installing
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  Found Python %PYVER%

:: Create virtual environment
echo.
echo [2/4] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  Created venv/
) else (
    echo  venv/ already exists, skipping.
)

:: Activate and install dependencies
echo.
echo [3/4] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Dependency installation failed.
    echo  Check your internet connection and try again.
    pause
    exit /b 1
)
echo  Dependencies installed successfully.

:: Setup .env
echo.
echo [4/4] Checking configuration...
if not exist ".env" (
    copy .env.example .env >nul
    echo  Created .env from template.
    echo.
    echo  ============================================
    echo   IMPORTANT: Edit .env and add your API keys
    echo  ============================================
    echo.
    echo  Required:  ANTHROPIC_API_KEY
    echo  Optional:  VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY
    echo.
    notepad .env
) else (
    echo  .env already exists.
)

echo.
echo  ====================================================
echo   Setup complete! Run the agent with:
echo.
echo     start-cli.bat    - Interactive terminal chat
echo     start-web.bat    - Web UI + API server
echo     test-tools.bat   - Quick tool tests
echo  ====================================================
echo.
pause
