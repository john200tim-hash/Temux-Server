@echo off
title Tecno Server Control Hub
color 0B
set ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
set PHONE_IP=192.168.1.126
set SCRCPY=%~dp0scrcpy-win64-v2.4\scrcpy.exe

:MENU
cls
echo ========================================================
echo        TECNO POP 4 PRO - CENTRAL CONTROL HUB
echo        IP: %PHONE_IP%  ^|  Node: Headless Linux Server
echo ========================================================
echo.
echo   [1] Connect Wireless ADB ^& Enable Always-On Screen
echo   [2] Check Server Status ^& Live WAF Metrics
echo   [3] Open GUI Dashboard in Browser (http://%PHONE_IP%:8000/dashboard)
echo   [4] Launch Screen Mirror (Scrcpy)
echo   [5] Open Direct ADB Shell (No Password)
echo   [6] Open SSH Terminal (Termux)
echo   [7] Deploy File to Phone (/sdcard/Download/)
echo   [8] Full Auto-Start Sequence (Connect + Check Status)
echo   [0] Exit
echo.
echo ========================================================
set /p choice="Select an option (0-8): "

if "%choice%"=="1" goto CONNECT
if "%choice%"=="2" goto STATUS
if "%choice%"=="3" goto DASHBOARD
if "%choice%"=="4" goto MIRROR
if "%choice%"=="5" goto ADBSHELL
if "%choice%"=="6" goto SSHTERM
if "%choice%"=="7" goto DEPLOY
if "%choice%"=="8" goto AUTOSTART
if "%choice%"=="0" exit /b
goto MENU

:CONNECT
cls
echo [*] Connecting to %PHONE_IP%:5555...
"%ADB%" connect %PHONE_IP%:5555
timeout /t 2 /nobreak >nul
echo.
echo [*] Keeping screen awake...
"%ADB%" -s %PHONE_IP%:5555 shell "svc power stayon true; settings put system screen_off_timeout 2147483647; settings put global stay_on_while_plugged_in 7"
echo.
pause
goto MENU

:STATUS
cls
call "%~dp0scripts\status.bat"
goto MENU

:DASHBOARD
start http://%PHONE_IP%:8000/dashboard
goto MENU

:MIRROR
cls
echo [*] Launching Scrcpy...
start "" "%SCRCPY%" -s %PHONE_IP%:5555 -m 800 -b 2M --max-fps 30
goto MENU

:ADBSHELL
cls
call "%~dp0scripts\adb_shell.bat"
goto MENU

:SSHTERM
cls
call "%~dp0scripts\ssh.bat"
goto MENU

:DEPLOY
cls
call "%~dp0scripts\deploy.bat"
goto MENU

:AUTOSTART
cls
echo [*] Running full startup sequence...
call "%~dp0scripts\connect.bat"
call "%~dp0scripts\status.bat"
goto MENU
