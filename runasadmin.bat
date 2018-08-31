@echo off
set /p proc=Which program would like to runas Admin (powershell,code): 
powershell -Command "Start-Process %proc% -Verb RunAs"