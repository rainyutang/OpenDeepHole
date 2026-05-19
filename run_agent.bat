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

call :ADD_DEFAULT_MSYS2_PATHS

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

call :ADD_DEFAULT_MSYS2_PATHS

where semgrep >nul 2>nul
if errorlevel 1 (
    echo semgrep command not found after installing dependencies.
    exit /b 1
)

call :CHECK_SOURCE_INDEX_TOOLS
if errorlevel 1 exit /b 1

%PYTHON_CMD% -m agent.main %*
exit /b %ERRORLEVEL%

:ADD_DEFAULT_MSYS2_PATHS
if exist "C:\msys64\ucrt64\bin\ctags.exe" set "PATH=C:\msys64\ucrt64\bin;%PATH%"
if exist "C:\msys64\usr\bin\cscope.exe" set "PATH=C:\msys64\usr\bin;%PATH%"
exit /b 0

:PRINT_MSYS2_SOURCE_TOOL_HELP
echo Required source indexing tools are missing.
echo Recommended Windows install method: MSYS2 UCRT64.
echo 1. Install MSYS2 from https://www.msys2.org/
echo 2. Open "MSYS2 UCRT64" from the Start menu and run:
echo    pacman -Syu
echo    pacman -S --needed mingw-w64-ucrt-x86_64-ctags cscope
echo 3. If you run this .bat from cmd or PowerShell, add these directories to PATH:
echo    C:\msys64\ucrt64\bin
echo    C:\msys64\usr\bin
exit /b 0

:CHECK_SOURCE_INDEX_TOOLS
set "SOURCE_TOOL_MISSING="
where ctags >nul 2>nul
if errorlevel 1 set "SOURCE_TOOL_MISSING=1"

where cscope >nul 2>nul
if errorlevel 1 set "SOURCE_TOOL_MISSING=1"

if defined SOURCE_TOOL_MISSING (
    call :PRINT_MSYS2_SOURCE_TOOL_HELP
    exit /b 1
)

ctags --version 2>nul | findstr /C:"Universal Ctags" >nul
if errorlevel 1 (
    echo ctags must be Universal Ctags.
    call :PRINT_MSYS2_SOURCE_TOOL_HELP
    exit /b 1
)
exit /b 0
