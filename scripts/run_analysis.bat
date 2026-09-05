@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
rem Optional settings file; environment values otherwise remain in effect.
if not "%~1"=="" call "%~1"
if errorlevel 1 exit /b 10
if not defined TJ_VERIFICATION set "TJ_VERIFICATION=full"
if "%TJ_VERIFICATION%"=="full" goto :mode_ok
if "%TJ_VERIFICATION%"=="basic" goto :mode_ok
echo ERROR: TJ_VERIFICATION must be full or basic. 1>&2
exit /b 10
:mode_ok
if not defined TJ_LOG_DIR goto :missing_settings
if not defined TJ_SLICE_CONFIG goto :missing_settings
if not defined TJ_OUTPUT_ROOT set "TJ_OUTPUT_ROOT=%~dp0..\output"
if not defined TJ_PYTHON set "TJ_PYTHON=python.exe"
if not defined TJ_TOOL_DIR set "TJ_TOOL_DIR=%~dp0..\tools\one_c_tj_analyzer"
if not defined TJ_CAPTURE_ID set "TJ_CAPTURE_ID=local-capture"
if not defined TJ_ARCHIVE_MODE set "TJ_ARCHIVE_MODE=auto"
if not defined TJ_TOP_CALLS set "TJ_TOP_CALLS=500"
if not exist "%TJ_LOG_DIR%\" goto :missing_settings
if not exist "%TJ_SLICE_CONFIG%" goto :missing_settings
"%TJ_PYTHON%" -B "%TJ_TOOL_DIR%\analyze_1c_tj.py" --version >nul || exit /b 14
if "%~2"=="--check" exit /b 0
for /f %%I in ('powershell.exe -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss_fff"') do set "TJ_RUN_ID=%%I"
if not defined TJ_RUN_ID exit /b 15
set "TJ_RUN_DIR=%TJ_OUTPUT_ROOT%\run_%TJ_RUN_ID%"
if exist "%TJ_RUN_DIR%" exit /b 12
mkdir "%TJ_RUN_DIR%" || exit /b 12
echo [1/4] Analysis, verification=%TJ_VERIFICATION%
"%TJ_PYTHON%" -B "%TJ_TOOL_DIR%\analyze_1c_tj.py" "%TJ_LOG_DIR%" --output-dir "%TJ_RUN_DIR%\analysis" --capture-id "%TJ_CAPTURE_ID%" --archive-mode "%TJ_ARCHIVE_MODE%" --top-calls "%TJ_TOP_CALLS%" --verification "%TJ_VERIFICATION%" --progress
if errorlevel 1 goto :failed
if "%TJ_VERIFICATION%"=="basic" goto :slices
echo [2/4] Full analysis verification
"%TJ_PYTHON%" -B "%TJ_TOOL_DIR%\verify_analysis.py" --analysis-dir "%TJ_RUN_DIR%\analysis"
if errorlevel 1 goto :failed
:slices
echo [3/4] Slices, verification=%TJ_VERIFICATION%
"%TJ_PYTHON%" -B "%TJ_TOOL_DIR%\derive_slices.py" --analysis-dir "%TJ_RUN_DIR%\analysis" --config "%TJ_SLICE_CONFIG%" --output-dir "%TJ_RUN_DIR%\slices" --verification "%TJ_VERIFICATION%"
if errorlevel 1 goto :failed
if "%TJ_VERIFICATION%"=="basic" goto :done
echo [4/4] Full slice verification
"%TJ_PYTHON%" -B "%TJ_TOOL_DIR%\verify_slices.py" --analysis-dir "%TJ_RUN_DIR%\analysis" --slices-dir "%TJ_RUN_DIR%\slices"
if errorlevel 1 goto :failed
:done
if "%TJ_VERIFICATION%"=="basic" echo Расчёт завершён. Полная верификация не выполнялась. Этапы 2 и 4 пропущены.
echo Results: "%TJ_RUN_DIR%"
exit /b 0
:missing_settings
echo ERROR: Set TJ_LOG_DIR and TJ_SLICE_CONFIG to existing paths. 1>&2
exit /b 11
:failed
echo ERROR: Pipeline stopped. Inspect "%TJ_RUN_DIR%". 1>&2
exit /b 20
