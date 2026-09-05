@echo off
set "TJ_VERIFICATION=full"
set "TJ_LOG_DIR=C:\Path\To\1clogs"
set "TJ_OUTPUT_ROOT=%~dp0..\output"
set "TJ_SLICE_CONFIG=%~dp0..\tools\one_c_tj_analyzer\configs\slices.example.json"
set "TJ_CAPTURE_ID=local-capture"
rem Optional: set TJ_PYTHON to the full path of python.exe.
