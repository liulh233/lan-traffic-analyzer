@echo off
setlocal
rem Enumerate LAN devices: ping sweep + ARP table + OUI vendor lookup
set "PY="
py -3 -c "import sys; assert sys.version_info >= (3, 8)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
    python -c "import sys; assert sys.version_info >= (3, 8)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    python3 -c "import sys; assert sys.version_info >= (3, 8)" >nul 2>&1 && set "PY=python3"
)
if not defined PY (
    echo [ERROR] Python 3.8 or newer is required.
    exit /b 1
)

%PY% "%~dp0scan_lan.py" %*
exit /b %errorlevel%
