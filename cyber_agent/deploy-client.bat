@echo off
title Cybersecurity AI Agent - Client Setup
cd /d "%~dp0"
echo.
echo  ====================================================
echo   Cybersecurity AI Agent - CLIENT Setup
echo   For devices connecting to a remote server
echo  ====================================================
echo.

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] Python not installed. Download from https://www.python.org/downloads/
    echo  Check "Add Python to PATH" during install.
    pause
    exit /b 1
)

:: Setup venv for local CLI
if not exist "venv" (
    echo [1/3] Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt -q
    echo  Dependencies installed.
) else (
    call venv\Scripts\activate.bat
    echo [1/3] Virtual environment ready.
)

:: Configure .env
echo.
echo [2/3] Configuring client...
if not exist ".env" (
    copy .env.example .env >nul
)

echo.
echo  ====================================================
echo   Enter the SERVER connection details:
echo  ====================================================
echo.
set /p SERVER_IP="  Server IP address: "
set /p SERVER_API_KEY="  API Key: "
echo.

:: Write client config
echo # Client Configuration > .env.client
echo SERVER_URL=https://%SERVER_IP%:8000>> .env.client
echo SERVER_API_KEY=%SERVER_API_KEY%>> .env.client
echo  Saved to .env.client

echo.
echo [3/3] Testing connection...
echo.
curl -k -s -o nul -w "  HTTPS Status: %%{http_code}\n" "https://%SERVER_IP%:8000/health"
if %ERRORLEVEL% neq 0 (
    echo  [WARN] Could not reach server. Check IP and firewall.
) else (
    echo  Connection successful!
)

echo.
echo  ====================================================
echo   CLIENT READY
echo  ====================================================
echo.
echo  Local CLI:  start-cli.bat  (uses local Anthropic key)
echo  Web UI:     Open https://%SERVER_IP%:8000 in browser
echo              (Accept the self-signed cert warning)
echo.
pause
