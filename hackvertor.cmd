@echo off
rem ---------------------------------------------------------------------------
rem hackvertor.cmd - run hackvertor.sh from cmd.exe or PowerShell on Windows.
rem
rem It locates Git Bash (or a bash on PATH) and forwards all arguments and
rem standard input, so both of these work:
rem
rem     hackvertor.cmd -base64 "admin' OR 1=1--"
rem     type content.txt | hackvertor.cmd -base64
rem
rem NOTE: this launcher is a convenience wrapper and is not covered by the test
rem suite (tests/run-tests.sh exercises hackvertor.sh directly).
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

set "HERE=%~dp0"
set "BASH="

if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH=%ProgramFiles%\Git\bin\bash.exe"
if not defined BASH if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "BASH=%ProgramFiles(x86)%\Git\bin\bash.exe"
if not defined BASH if exist "%LOCALAPPDATA%\Programs\Git\bin\bash.exe" set "BASH=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
if not defined BASH for %%B in (bash.exe) do if not defined BASH set "BASH=%%~$PATH:B"

if not defined BASH (
    echo hackvertor: bash not found. Install Git for Windows or run hackvertor.sh from a POSIX shell. 1>&2
    exit /b 127
)

rem Convert the script path to the /c/... form MSYS expects.
set "SCRIPT=%HERE%hackvertor.sh"
set "SCRIPT=%SCRIPT:\=/%"
set "DRIVE=%SCRIPT:~0,1%"
set "SCRIPT=/%DRIVE%/%SCRIPT:~3%"

"%BASH%" "%SCRIPT%" %*
exit /b %ERRORLEVEL%
