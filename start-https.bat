@echo off
setlocal
cd /d "%~dp0"
set "USE_HTTPS=true"
call "%~dp0start-demo.bat" --https %*
exit /b %ERRORLEVEL%
