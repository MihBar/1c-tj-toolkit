@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"

if defined PYTHON (
    set "TJ_PYTHON=%PYTHON%"
) else (
    where py >nul 2>nul
    if not errorlevel 1 (
        set "TJ_PYTHON=py"
        set "TJ_PYTHON_ARG=-3"
    ) else (
        where python >nul 2>nul
        if errorlevel 1 (
            echo ERROR: Python 3 was not found. Install Python or set PYTHON to its executable path. 1>&2
            exit /b 127
        )
        set "TJ_PYTHON=python"
    )
)

if "%~1"=="" goto :help
if /I "%~1"=="help" goto :help
if /I "%~1"=="--help" goto :help
if /I "%~1"=="-h" goto :help

set "COMMAND=%~1"
shift
set "FORWARD_ARGS="

:collect_args
if "%~1"=="" goto :dispatch
set "FORWARD_ARGS=%FORWARD_ARGS% "%~1""
shift
goto :collect_args

:dispatch
if /I "%COMMAND%"=="analyze" goto :analyze
if /I "%COMMAND%"=="verify" goto :verify
if /I "%COMMAND%"=="slices" goto :slices
if /I "%COMMAND%"=="report" goto :report
if /I "%COMMAND%"=="test" goto :test
if /I "%COMMAND%"=="test-analyzer" goto :test_analyzer
if /I "%COMMAND%"=="test-report" goto :test_report
if /I "%COMMAND%"=="check-data" goto :check_data

echo ERROR: Unknown command "%COMMAND%". 1>&2
goto :help_error

:analyze
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B tools\one_c_tj_analyzer\analyze_1c_tj.py %FORWARD_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:verify
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B tools\one_c_tj_analyzer\verify_analysis.py %FORWARD_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:slices
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B tools\one_c_tj_analyzer\derive_slices.py %FORWARD_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:report
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B tools\one_c_tj_report\build_report.py %FORWARD_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:test
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B -m unittest discover -s tools\one_c_tj_analyzer\tests -v
if errorlevel 1 (
    set "EXIT_CODE=1"
    popd
    exit /b 1
)
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B -m unittest discover -s tools\one_c_tj_report\tests -v
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:test_analyzer
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B -m unittest discover -s tools\one_c_tj_analyzer\tests -v
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:test_report
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B -m unittest discover -s tools\one_c_tj_report\tests -v
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:check_data
pushd "%REPO_ROOT%" || exit /b 1
call "%TJ_PYTHON%" %TJ_PYTHON_ARG% -B -m unittest discover -s tools\one_c_tj_report\tests -p test_saved_contract.py -v
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:help
echo Usage: scripts\run.cmd COMMAND [ARGUMENTS]
echo.
echo Commands:
echo   analyze        Analyze a TJ directory or supported archives
echo   verify         Verify a saved analysis bundle
echo   slices         Build analytical slices from a saved bundle
echo   report         Build the overview PDF report
echo   test           Run analyzer and PDF test suites
echo   test-analyzer  Run analyzer tests only
echo   test-report    Run PDF module tests only
echo   check-data     Validate committed JSON, CSV and SQLite fixture contracts
echo.
echo Arguments after COMMAND are passed unchanged to the corresponding Python CLI.
echo Set PYTHON to a Python 3 executable path to override automatic detection.
exit /b 0

:help_error
echo Run scripts\run.cmd --help for usage. 1>&2
exit /b 2
