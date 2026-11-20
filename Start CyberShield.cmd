@echo off
setlocal
cd /d "%~dp0"
if not exist "windows-x64\cybershield.exe" (
  echo Extract the entire ZIP before starting CyberShield.
  pause
  exit /b 1
)
curl.exe -s -o nul --max-time 2 --noproxy "*" http://127.0.0.1:8080/
if not errorlevel 1 (
  echo A server is already using port 8080. If it is this version of CyberShield, open http://127.0.0.1:8080/
  echo To use this copy instead, close the previous server window and run this file again.
  pause
  exit /b 0
)
echo Open http://127.0.0.1:8080/ in your browser. Keep this window open while using CyberShield.
"windows-x64\cybershield.exe" "."
if errorlevel 1 pause
