@echo off
title Cybersecurity AI Agent - Tool Tests
cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo  [ERROR] Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

echo.
echo  ====================================================
echo   Cybersecurity AI Agent - Quick Tool Tests
echo  ====================================================
echo.

echo [TEST 1] CVE Search: log4j
echo -------------------------------------------------------
python cli.py cve "log4j"
echo.

echo [TEST 2] DNS Lookup: google.com (with security check)
echo -------------------------------------------------------
python cli.py dns google.com --security
echo.

echo [TEST 3] Single Query: "What is CVE-2021-44228?"
echo -------------------------------------------------------
python cli.py query "Briefly explain what CVE-2021-44228 is"
echo.

echo  ====================================================
echo   Tests complete!
echo  ====================================================
echo.
pause
