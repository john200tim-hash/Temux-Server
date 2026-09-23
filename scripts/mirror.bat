@echo off
title Tecno Server - Screen Mirror
color 0D
set PHONE_IP=192.168.1.126
set SCRCPY=%~dp0..\scrcpy-win64-v2.4\scrcpy.exe

echo ============================================
echo   Tecno Pop 4 Pro - Screen Mirror (Scrcpy)
echo   Connecting to %PHONE_IP%:5555
echo ============================================
echo.

if not exist "%SCRCPY%" (
    echo [ERROR] scrcpy.exe not found at:
    echo   %SCRCPY%
    echo.
    echo Make sure scrcpy-win64-v2.4 folder is in the same
    echo directory as this bat file.
    pause
    exit /b
)

echo [*] Starting mirror (800px, 30fps, 2Mbps)...
echo [*] Use your mouse and keyboard to control the phone.
echo [*] Close the window or press Ctrl+C to stop.
echo.
"%SCRCPY%" -s %PHONE_IP%:5555 -m 800 -b 2M --max-fps 30
