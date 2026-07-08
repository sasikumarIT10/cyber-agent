@echo off
title Cybersecurity AI Agent - Server Deployment
cd /d "%~dp0"
echo.
echo  ====================================================
echo   Cybersecurity AI Agent - SERVER Deployment
echo   For hosting the API + Web UI for remote devices
echo  ====================================================
echo.

:: Check venv
if not exist "venv\Scripts\activate.bat" (
    echo  [ERROR] Run setup.bat first!
    pause
    exit /b 1
)
call venv\Scripts\activate.bat

:: Install cryptography for TLS
echo [1/5] Installing TLS dependencies...
pip install cryptography -q

:: Generate TLS certs
echo.
echo [2/5] Generating TLS certificates...
if not exist "certs\server.crt" (
    python generate_certs.py
) else (
    echo  Certificates already exist in certs\
    echo  Delete certs\ folder and re-run to regenerate.
)

:: Configure .env for server mode
echo.
echo [3/5] Checking server configuration...
findstr /C:"SSL_ENABLED" .env >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.>> .env
    echo # --- Server Deployment Settings --->> .env
    echo SSL_ENABLED=true>> .env
    echo API_HOST=0.0.0.0>> .env
    echo # Add client IPs for extra security ^(comma-separated^)>> .env
    echo # IP_ALLOWLIST=192.168.1.10,10.0.0.5>> .env
    echo  Added server settings to .env
) else (
    echo  Server settings already in .env
)

:: Windows Firewall rule
echo.
echo [4/5] Configuring Windows Firewall...
echo  Adding inbound rule for port 8000...
netsh advfirewall firewall show rule name="CyberAgent API" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    netsh advfirewall firewall add rule name="CyberAgent API" dir=in action=allow protocol=tcp localport=8000 >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        echo  Firewall rule added successfully.
    ) else (
        echo  [WARN] Could not add firewall rule. Run as Administrator.
    )
) else (
    echo  Firewall rule already exists.
)

:: Display info
echo.
echo [5/5] Server ready!
echo.
echo  ====================================================
echo   DEPLOYMENT INFO
echo  ====================================================
echo.
echo  The server will start on https://0.0.0.0:8000
echo.
echo  Give each client device:
echo    1. The server IP address
echo    2. The API key from .env
echo    3. The certs\server.crt file (for cert trust)
echo.
echo  Security checklist:
echo    [x] HTTPS/TLS enabled
echo    [x] API key authentication
echo    [x] Rate limiting (30 req/min)
echo    [x] Brute-force lockout (10 fails = 15 min block)
echo    [x] Audit logging (audit.log)
echo    [ ] Set IP_ALLOWLIST in .env for extra security
echo    [ ] Set a persistent API_KEY in .env
echo.
echo  Press any key to start the server...
pause >nul

python api.py
