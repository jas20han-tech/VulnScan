@echo off
title VulnScan - Stop
rem Convenience wrapper so stop.ps1 can be run from cmd or by double-click.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop.ps1"
echo.
echo Press any key to close this window...
pause > nul
