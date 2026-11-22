@echo off
setlocal
cd /d "%~dp0"

set "USE_HTTPS_MODE=0"
if /i "%~1"=="--https" set "USE_HTTPS_MODE=1"
if /i "%~1"=="-https" set "USE_HTTPS_MODE=1"
if /i "%USE_HTTPS%"=="true" set "USE_HTTPS_MODE=1"

if "%USE_HTTPS_MODE%"=="1" goto :CONFIG_HTTPS

:CONFIG_HTTP
set "USE_HTTPS=false"
set "PROTOCOL=http"
set "SERVER_URL=http://127.0.0.1:4173"
set "TRANSPORT_DESC=Local-only HTTP bound strictly to 127.0.0.1"
title Secure Zero-Trust File Sharing Server (Local HTTP Demo)
goto :CONFIG_DONE

:CONFIG_HTTPS
set "USE_HTTPS=true"
set "PROTOCOL=https"
set "SERVER_URL=https://127.0.0.1:4173"
set "TRANSPORT_DESC=Encrypted TLS v1.2+ (EC P-256 self-signed)"
title Secure Zero-Trust File Sharing Server (HTTPS / TLS Demo)

:CONFIG_DONE
echo ======================================================================
echo           SECURE ZERO-TRUST FILE SHARING SYSTEM (DEMO)
echo ======================================================================
echo.
echo Server Address:  %SERVER_URL%
echo Transport Mode:  %PROTOCOL% (%TRANSPORT_DESC%)
echo Security Model:  Default-Deny (Authorization checked on every request)
echo Cryptography:    AES-256-GCM (fresh random IV) + SHA-256 integrity
echo.
echo Demo Accounts:
echo   - asha  / asha123   (Role: Student)
echo   - rao   / rao123    (Role: Faculty)
echo   - ravi  / ravi123   (Role: Student)
echo   - admin / admin123  (Role: Admin)
echo.

if not "%USE_HTTPS_MODE%"=="1" goto :START_SERVER

if not exist "storage\cert.pem" goto :GEN_CERT
if not exist "storage\key.pem" goto :GEN_CERT
goto :CERTS_READY

:GEN_CERT
echo [TLS SETUP] Incomplete or missing certificate pair. Generating self-signed EC P-256 TLS certificate...
node gen-cert.js --force
if errorlevel 1 (
    echo [ERROR] Failed to generate TLS certificate. Please check OpenSSL.
    pause
    exit /b 1
)
echo.

:CERTS_READY
echo Note: Because this uses a self-signed certificate for local testing,
echo your browser may display a certificate warning (NET::ERR_CERT_AUTHORITY_INVALID).
echo Click 'Advanced' -^> 'Proceed to 127.0.0.1' to continue.
echo.

:START_SERVER
echo Launching your default web browser to %SERVER_URL% ...
start "" "%SERVER_URL%"
echo.
echo [SERVER LOGS] Leave this window visible to monitor ALLOW / DENY events.
echo Press Ctrl+C in this console window to stop the server at any time.
echo ----------------------------------------------------------------------

node server.js
if errorlevel 1 (
    "C:\Program Files\nodejs\node.exe" server.js
)

echo.
echo Server has terminated.
pause
