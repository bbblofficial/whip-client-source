@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
set PATH=C:\Users\Java\vcpkg\downloads\tools\ninja\1.13.2-windows;%PATH%
cd /d "C:\Users\Java\Desktop\whip\WhipClient"
if exist build\prod-with-loader rmdir /s /q build\prod-with-loader
cmake --preset prod-with-loader
if exist build\prod-with-loader\build.ninja cmake --build build/prod-with-loader
echo EXIT_CODE=%ERRORLEVEL%
