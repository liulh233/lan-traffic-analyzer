@echo off
rem Mark a LAN device with a friendly name (writes devices.json)
rem usage: mark.bat 192.168.110.211 ljj电脑
rem        mark.bat --list
rem        mark.bat 192.168.110.211 --remove
setlocal
set "PY="
py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY (
    python -c "import sys" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    python3 -c "import sys" >nul 2>&1 && set "PY=python3"
)
if not defined PY (
    echo [ERROR] Python 3 not found.
    exit /b 1
)

%PY% "%~dp0mark_device.py" %*
