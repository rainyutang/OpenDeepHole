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

for /f "delims=" %%I in ('%PYTHON_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts') or '')" 2^>nul') do set "PYTHON_SCRIPTS=%%I"
if defined PYTHON_SCRIPTS set "PATH=%PYTHON_SCRIPTS%;%PATH%"

set "MISSING_DEPS="
%PYTHON_CMD% -c "import semgrep, httpx, websockets, yaml, pydantic, openai, tree_sitter, tree_sitter_cpp, uvicorn, fastapi; from mcp.server.fastmcp import FastMCP" 2>nul
if errorlevel 1 set "MISSING_DEPS=1"

where semgrep >nul 2>nul
if errorlevel 1 set "MISSING_DEPS=1"

if defined MISSING_DEPS (
    echo Installing agent dependencies...
    %PYTHON_CMD% -m pip install -r requirements-agent.txt || exit /b 1
    for /f "delims=" %%I in ('%PYTHON_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts') or '')" 2^>nul') do set "PYTHON_SCRIPTS=%%I"
    if defined PYTHON_SCRIPTS set "PATH=%PYTHON_SCRIPTS%;%PATH%"
)

where semgrep >nul 2>nul
if errorlevel 1 (
    echo semgrep command not found after installing dependencies.
    exit /b 1
)

%PYTHON_CMD% -m agent.main %*
