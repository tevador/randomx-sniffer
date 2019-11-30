@echo off
cd /d "%~dp0"
randomx-sniffer.exe -samples 5 -wait 50 -threshold 2
pause
