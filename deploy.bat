@echo off
title Tecno Server - Push & Deploy File
color 09
set ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
set PHONE_IP=192.168.1.126

echo ============================================
echo   Tecno Pop 4 Pro - Deploy File to Phone
echo ============================================
echo.

set "FILEPATH=%~1"

if "%FILEPATH%"=="" (
    echo You can drag and drop any file directly onto this .bat file.
    echo Or enter the full path to the file below:
    echo.
    set /p "FILEPATH=Enter file path: "
)

:: Strip surrounding quotes if present
set FILEPATH=%FILEPATH:"=%

if "%FILEPATH%"=="" (
    echo [ERROR] No file path provided.
    echo.
    pause
    exit /b
)

if not exist "%FILEPATH%" (
    echo [ERROR] File does not exist: "%FILEPATH%"
    echo.
    pause
    exit /b
)

for %%F in ("%FILEPATH%") do set "FILENAME=%%~nxF"

echo.
echo [*] Pushing "%FILENAME%" to /sdcard/Download/ ...
"%ADB%" -s %PHONE_IP%:5555 push "%FILEPATH%" "/sdcard/Download/%FILENAME%"

echo.
echo ============================================
echo [*] Transfer Complete!
echo     File location on phone: /sdcard/Download/%FILENAME%
echo.
echo     In Termux, run:
echo     cp /sdcard/Download/%FILENAME% ~/
echo ============================================
echo.
pause
