@echo off
setlocal

cd /d "%~dp0web"

echo ========================================
echo   Internship2 - Cryptography Demo
echo ========================================
echo.
echo URL:   http://localhost:3900/
echo Stop:  press Ctrl+C
echo ========================================
echo.

if not exist node_modules goto install
goto run

:install
echo [1/2] Installing dependencies, please wait...
call npm install --no-audit --no-fund
if errorlevel 1 goto fail

:run
echo [2/2] Starting Next.js dev server...
call npm run dev
goto :eof

:fail
echo.
echo [ERROR] npm install failed. Please check network or run manually:
echo     cd web
echo     npm install
pause
exit /b 1
