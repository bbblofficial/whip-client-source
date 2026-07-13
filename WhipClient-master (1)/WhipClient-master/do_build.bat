@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >/dev/null 2>&1
cd /d C:\Users\Java\Desktop\whip\WhipClient
cmake --build build\dev-standalone --target inject -j 14
