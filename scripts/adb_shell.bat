@echo off
title Tecno Server - Direct ADB Shell
color 0F
set ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
set PHONE_IP=192.168.1.126

echo ============================================
echo   Tecno Pop 4 Pro - Direct ADB Shell
echo   (No password required)
echo ============================================
echo.
"%ADB%" -s %PHONE_IP%:5555 shell
echo.
pause
