@echo off
setlocal

REM Initialize Visual Studio 2022 Community environment
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

REM Clean and reconfigure with Ninja
if exist build\dev-standalone rmdir /s /q build\dev-standalone
cmake --preset dev-standalone

REM Build
cmake --build build/dev-standalone --config Release

echo.
echo Build complete!
pause
