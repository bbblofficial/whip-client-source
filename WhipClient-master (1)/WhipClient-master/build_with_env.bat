@echo off
REM Initialize Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

REM Configure CMake
cmake --preset dev-standalone

REM Build
cmake --build build/dev-standalone --config Release

echo Build complete!
