@echo off
title Cybersecurity AI Agent - Web Server
cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo  [ERROR] Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

echo.
echo  ====================================================
echo   Cybersecurity AI Agent - Web Server
echo  ====================================================
echo.
echo  Starting server... The web UI will open in your browser.
echo  Press Ctrl+C to stop the server.
echo.

:: Open browser after a short delay
start "" cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:8000"

python api.py
