@echo off
rem One command: connect this laptop's Ollama (127.0.0.1:11434, never exposed) to the
rem Render-hosted LogSentinel chat through an authenticated gateway + ngrok tunnel.
setlocal
cd /d "%~dp0.."
if exist "venv\Scripts\python.exe" (set "PY=venv\Scripts\python.exe") else (set "PY=python")
"%PY%" tools\connect_ollama.py %*
endlocal
