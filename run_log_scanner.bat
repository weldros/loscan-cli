@echo off
REM Windows batch script to run log scanner with interactive prompts
REM Usage: run_log_scanner.bat

setlocal enabledelayedexpansion

REM Check Python 3 is installed
python3 --version >nul 2>&1
if errorlevel 1 (
    echo Python 3 is not installed. Please install Python 3.8+
    pause
    exit /b 1
)

REM Get the directory where this script is located
set "repo_dir=%~dp0"
set "repo_dir=%repo_dir:~0,-1%"
set "error_dir=%repo_dir%\error"
set "python_script=%repo_dir%\scripts\log_scanner.py"

REM Create error directory if it doesn't exist
if not exist "%error_dir%" (
    mkdir "%error_dir%"
)

REM Prompt for log file path
set "log_file="
set /p "log_file=Enter path to .log file: "

if "!log_file!"=="" (
    echo No input file provided.
    pause
    exit /b 1
)

if not exist "!log_file!" (
    echo File not found: !log_file!
    pause
    exit /b 1
)

set "report_username="
set /p "report_username=Set report username (leave blank to disable login): "
set "extra_args="
if not "!report_username!"=="" (
    set "report_password="
    set /p "report_password=Set report password: "
    set "extra_args=--report-username !report_username! --report-password !report_password!"
)

REM Prompt for output formats — pre-initialize to empty so Enter works
set "formats="
set /p "formats=Enter output formats (json,csv,html,yaml,db) or leave blank for all: "

REM Call Python CLI
if "!formats!"=="" (
    python3 "!python_script!" "!log_file!" --output-dir "!error_dir!" --tui !extra_args!
) else (
    python3 "!python_script!" "!log_file!" --output-dir "!error_dir!" --formats "!formats!" --tui !extra_args!
)

echo.
echo Done.
pause

endlocal