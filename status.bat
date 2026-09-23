@echo off
title Tecno Server - WAF Gateway Status
color 0E
set ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
set PHONE_IP=192.168.1.126
set ADMIN_TOKEN=supersecret-gateway-token-2026

echo ============================================
echo   Tecno Pop 4 Pro - Security Gateway Status
echo ============================================
echo.

echo [*] Checking ADB connection...
"%ADB%" -s %PHONE_IP%:5555 get-state 2>nul | find "device" >nul
if errorlevel 1 (
    echo [!] Device not connected. Running connect first...
    "%ADB%" connect %PHONE_IP%:5555
    timeout /t 2 /nobreak >nul
)

echo [*] Checking listening ports...
"%ADB%" -s %PHONE_IP%:5555 shell "netstat -tuln 2>/dev/null | grep -E ':8000|:8022'"

echo.
echo [*] Gateway Health Check:
curl -s --max-time 3 http://%PHONE_IP%:8000/health
echo.

echo.
echo [*] Gateway Metrics (Threats + Requests):
curl -s --max-time 3 -H "X-Admin-Token: %ADMIN_TOKEN%" http://%PHONE_IP%:8000/admin/metrics
echo.

echo.
echo ============================================
echo   Open http://%PHONE_IP%:8000 in browser
echo   Admin dashboard at /admin/metrics
echo ============================================
pause
