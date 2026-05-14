@echo off
REM OpenDeepHole Agent - Windows startup script
REM
REM Usage:
REM   run_agent.bat <project_path> [OPTIONS]
REM
REM Examples:
REM   run_agent.bat C:\path\to\source
REM   run_agent.bat C:\path\to\source --server http://192.168.1.10:8000
REM   run_agent.bat C:\path\to\source --checkers npd,oob --name "MyProject"
REM   run_agent.bat C:\path\to\source --dry-run
REM
REM Before first run: edit agent.yaml to set server_url and llm_api.api_key

cd /d "%~dp0"

where python3 >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON_CMD=python3"
) else (
    set "PYTHON_CMD=python"
)

%PYTHON_CMD% -c "import httpx" 2>nul || (
    echo Installing agent dependencies...
    %PYTHON_CMD% -m pip install -r requirements-agent.txt
)

%PYTHON_CMD% -m agent.main %*
