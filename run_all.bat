@echo off
start "RippleGuard API" cmd /k "cd /d %~dp0backend && run_backend.bat"
start "RippleGuard UI" cmd /k "cd /d %~dp0frontend && run_frontend.bat"
timeout /t 6 >nul
start http://127.0.0.1:5600
