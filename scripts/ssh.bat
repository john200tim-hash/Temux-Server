@echo off
title Tecno Server - SSH Shell
color 0B
set PHONE_IP=192.168.1.126

echo ============================================
echo   Tecno Pop 4 Pro - SSH Terminal
echo   IP: %PHONE_IP% | Port: 8022
echo   Password: technoserver
echo ============================================
echo.

where ssh >nul 2>nul
if errorlevel 1 (
    echo [ERROR] OpenSSH client 'ssh' is not installed or not in PATH.
    echo Opening ADB shell fallback instead...
    pause
    "%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe" -s %PHONE_IP%:5555 shell
    exit /b
)

echo [*] Connecting to %PHONE_IP%:8022 ...
ssh -p 8022 %PHONE_IP%

echo.
echo ============================================
echo   Session ended.
echo ============================================
pause
