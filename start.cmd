@echo off
title VulnScan - Start
rem Convenience wrapper so start.ps1 can be run from cmd or by double-click.
rem Keeps the window open so you can read the status/URLs; the services are
rem started detached in the background and keep running after this closes.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1"
echo.
echo ---------------------------------------------------------------
echo  VulnScan is starting. Open the frontend when ready:
echo    http://localhost:5173
echo  API docs: http://localhost:8000/docs
echo  Stop everything later with:  .\stop.cmd
echo ---------------------------------------------------------------
echo.
echo Press any key to close this window (services keep running)...
pause > nul
