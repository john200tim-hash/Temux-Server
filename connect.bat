@echo off
title Tecno Server - ADB Connect
color 0A
set ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
set PHONE_IP=192.168.1.126

echo ============================================
echo   Tecno Pop 4 Pro - Wireless ADB Connect
echo ============================================
echo.
echo [*] Connecting to %PHONE_IP%:5555...
"%ADB%" connect %PHONE_IP%:5555
timeout /t 1 /nobreak >nul

echo.
echo [*] Connected Devices:
"%ADB%" devices

echo.
echo [*] Keeping screen always on...
"%ADB%" -s %PHONE_IP%:5555 shell "svc power stayon true; settings put system screen_off_timeout 2147483647"

echo.
echo ============================================
echo   DONE! Device is connected wirelessly.
echo   Run ssh.bat to open a shell.
echo   Run mirror.bat to mirror the screen.
echo ============================================
pause
