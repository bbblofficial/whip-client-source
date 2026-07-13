@echo off
cd /d "%~dp0"

echo.
echo =========================================
echo         WhipClient DLL Injector
echo =========================================
echo.

set "PROCESS_NAME=javaw.exe"
set "FALLBACK_PROCESS=java.exe"
set "BIN_PATH="

REM Auto-detect build directory (check multiple possible locations, prod first)
if exist "%~dp0build\prod-with-loader\bin\WhipClient.dll" (
    set "BIN_PATH=%~dp0build\prod-with-loader\bin"
    echo [INFO] Using prod-with-loader build
) else if exist "%~dp0build\dev-with-loader\bin\WhipClient.dll" (
    set "BIN_PATH=%~dp0build\dev-with-loader\bin"
    echo [INFO] Using dev-with-loader build
) else if exist "%~dp0build\dev-standalone\bin\WhipClient.dll" (
    set "BIN_PATH=%~dp0build\dev-standalone\bin"
    echo [INFO] Using dev-standalone build
) else if exist "%~dp0cmake-build-debug-visual-studio\bin\WhipClient.dll" (
    set "BIN_PATH=%~dp0cmake-build-debug-visual-studio\bin"
    echo [INFO] Using cmake-build-debug-visual-studio
) else if exist "%~dp0cmake-build-release\bin\WhipClient.dll" (
    set "BIN_PATH=%~dp0cmake-build-release\bin"
    echo [INFO] Using cmake-build-release
) else (
    echo [ERREUR] Aucun build de WhipClient trouve !
    echo.
    echo Repertoires verifies:
    echo   - build\dev-standalone\bin
    echo   - build\dev-with-loader\bin
    echo   - build\prod-with-loader\bin
    echo   - cmake-build-debug-visual-studio\bin
    echo   - cmake-build-release\bin
    echo.
    echo Veuillez compiler le projet d'abord avec CMake.
    echo.
    pause
    exit /b 1
)

set "VMP_DLL=%BIN_PATH%\VMProtectSDK64.dll"
set "CLIENT_DLL=%BIN_PATH%\WhipClient.dll"

REM Verification des DLLs
if not exist "%VMP_DLL%" (
    echo [ERREUR] VMP DLL non trouvee: %VMP_DLL%
    pause
    exit /b 1
)

if not exist "%CLIENT_DLL%" (
    echo [ERREUR] WhipClient DLL non trouvee: %CLIENT_DLL%
    pause
    exit /b 1
)

echo [INFO] VMP DLL trouvee: %VMP_DLL%
echo [INFO] Client DLL trouvee: %CLIENT_DLL%
echo.

REM Recherche : Lunar (javaw.exe) puis Menoria (java.exe filtre par chemin .menoria)
echo [INFO] Recherche de Lunar Client (javaw.exe) ou Menoria (java.exe avec .menoria dans le chemin)...
set "PID="
set "FOUND_PROC="

call :search_client

REM Pas trouve : on attend que l'utilisateur lance le client
echo [ATTENTION] Aucun client detecte ^(ni javaw.exe ni java.exe Menoria^) !
echo.
echo Lancez Lunar Client ou Menoria, puis appuyez sur une touche...
pause >NUL

call :search_client

echo [ERREUR] Aucun client detecte !
pause
exit /b 1

:found_pid
echo [SUCCESS] Client detecte ! Process: %FOUND_PROC% PID: %PID%
echo.

REM ========================================
REM   Injection VMP + WhipClient en UN seul appel PowerShell
REM   (evite la double compilation Add-Type qui coute 3-5s a chaque fois)
REM ========================================
echo [INFO] Injection des DLLs (VMP puis WhipClient)...
echo.

REM Genere un script PS temporaire (plus fiable que de tout passer en -Command avec des ^ de continuation)
set "PS_SCRIPT=%TEMP%\whip_inject_%RANDOM%.ps1"

>  "%PS_SCRIPT%" echo Add-Type -TypeDefinition @'
>> "%PS_SCRIPT%" echo using System;
>> "%PS_SCRIPT%" echo using System.Runtime.InteropServices;
>> "%PS_SCRIPT%" echo using System.Text;
>> "%PS_SCRIPT%" echo public class Injector{
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern IntPtr VirtualAllocEx(IntPtr p,IntPtr a,uint s,uint t,uint pr);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern bool WriteProcessMemory(IntPtr p,IntPtr a,byte[] b,uint s,out uint w);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern IntPtr CreateRemoteThread(IntPtr p,IntPtr a,uint s,IntPtr st,IntPtr pa,uint f,IntPtr t);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr m,string n);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern IntPtr GetModuleHandle(string n);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern uint WaitForSingleObject(IntPtr h,uint m);
>> "%PS_SCRIPT%" echo [DllImport("kernel32.dll")]public static extern IntPtr GetCurrentProcess();
>> "%PS_SCRIPT%" echo [DllImport("advapi32.dll",SetLastError=true)]public static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
>> "%PS_SCRIPT%" echo [DllImport("advapi32.dll",SetLastError=true)]public static extern bool LookupPrivilegeValue(string s,string n,ref long v);
>> "%PS_SCRIPT%" echo [DllImport("advapi32.dll",SetLastError=true)]public static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TOKEN_PRIVILEGES n,uint b,IntPtr p,IntPtr r);
>> "%PS_SCRIPT%" echo [StructLayout(LayoutKind.Sequential)]public struct TOKEN_PRIVILEGES{public uint Count;public long Luid;public uint Attr;}
>> "%PS_SCRIPT%" echo public static bool EnableDebugPriv(){
>> "%PS_SCRIPT%" echo IntPtr tok;
>> "%PS_SCRIPT%" echo if(!OpenProcessToken(GetCurrentProcess(),0x20^|0x8,out tok))return false;
>> "%PS_SCRIPT%" echo long luid=0;
>> "%PS_SCRIPT%" echo if(!LookupPrivilegeValue(null,"SeDebugPrivilege",ref luid)){CloseHandle(tok);return false;}
>> "%PS_SCRIPT%" echo var tp=new TOKEN_PRIVILEGES{Count=1,Luid=luid,Attr=2};
>> "%PS_SCRIPT%" echo bool r=AdjustTokenPrivileges(tok,false,ref tp,0,IntPtr.Zero,IntPtr.Zero);
>> "%PS_SCRIPT%" echo CloseHandle(tok);
>> "%PS_SCRIPT%" echo return r ^&^& Marshal.GetLastWin32Error()==0;
>> "%PS_SCRIPT%" echo }
>> "%PS_SCRIPT%" echo public static IntPtr Open(uint pid){return OpenProcess(0x1F0FFF,false,pid);}
>> "%PS_SCRIPT%" echo public static IntPtr OpenLimited(uint pid){return OpenProcess(0x043A,false,pid);}
>> "%PS_SCRIPT%" echo public static int LastErr(){return Marshal.GetLastWin32Error();}
>> "%PS_SCRIPT%" echo public static bool InjectInto(IntPtr proc,string dll){
>> "%PS_SCRIPT%" echo try{
>> "%PS_SCRIPT%" echo var mem=VirtualAllocEx(proc,IntPtr.Zero,(uint)(dll.Length+1),0x3000,0x40);
>> "%PS_SCRIPT%" echo if(mem==IntPtr.Zero)return false;
>> "%PS_SCRIPT%" echo uint w;
>> "%PS_SCRIPT%" echo if(!WriteProcessMemory(proc,mem,Encoding.Default.GetBytes(dll),(uint)(dll.Length+1),out w))return false;
>> "%PS_SCRIPT%" echo var ll=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryA");
>> "%PS_SCRIPT%" echo if(ll==IntPtr.Zero)return false;
>> "%PS_SCRIPT%" echo var th=CreateRemoteThread(proc,IntPtr.Zero,0,ll,mem,0,IntPtr.Zero);
>> "%PS_SCRIPT%" echo if(th==IntPtr.Zero)return false;
>> "%PS_SCRIPT%" echo WaitForSingleObject(th,0xFFFFFFFF);
>> "%PS_SCRIPT%" echo CloseHandle(th);
>> "%PS_SCRIPT%" echo return true;
>> "%PS_SCRIPT%" echo }catch{return false;}
>> "%PS_SCRIPT%" echo }
>> "%PS_SCRIPT%" echo }
>> "%PS_SCRIPT%" echo '@
>> "%PS_SCRIPT%" echo if ([Injector]::EnableDebugPriv()) { Write-Host '[INFO] SeDebugPrivilege active' -ForegroundColor Cyan } else { Write-Host '[WARN] SeDebugPrivilege non active (relancer en admin si necessaire)' -ForegroundColor Yellow }
>> "%PS_SCRIPT%" echo $proc = [Injector]::Open(%PID%)
>> "%PS_SCRIPT%" echo if ($proc -eq [IntPtr]::Zero) {
>> "%PS_SCRIPT%" echo   $err = [Injector]::LastErr()
>> "%PS_SCRIPT%" echo   Write-Host "[WARN] OpenProcess (ALL_ACCESS) refuse, code=$err. Tentative avec acces limite..." -ForegroundColor Yellow
>> "%PS_SCRIPT%" echo   $proc = [Injector]::OpenLimited(%PID%)
>> "%PS_SCRIPT%" echo }
>> "%PS_SCRIPT%" echo if ($proc -eq [IntPtr]::Zero) {
>> "%PS_SCRIPT%" echo   $err = [Injector]::LastErr()
>> "%PS_SCRIPT%" echo   Write-Host "[ERREUR] OpenProcess a echoue ! Code=$err (5=ACCESS_DENIED, 87=INVALID_PARAMETER)" -ForegroundColor Red
>> "%PS_SCRIPT%" echo   Write-Host "[INFO] Lance le script en mode administrateur (clic droit -^> Executer en tant qu'admin)" -ForegroundColor Yellow
>> "%PS_SCRIPT%" echo   exit 1
>> "%PS_SCRIPT%" echo }
>> "%PS_SCRIPT%" echo if ([Injector]::InjectInto($proc, '%VMP_DLL%'))    { Write-Host '[SUCCESS] VMP DLL injectee !'        -ForegroundColor Green } else { Write-Host '[ERREUR] Echec injection VMP !'        -ForegroundColor Red; [Injector]::CloseHandle($proc); exit 1 }
>> "%PS_SCRIPT%" echo if ([Injector]::InjectInto($proc, '%CLIENT_DLL%')) { Write-Host '[SUCCESS] WhipClient DLL injectee !' -ForegroundColor Green } else { Write-Host '[ERREUR] Echec injection WhipClient !' -ForegroundColor Red; [Injector]::CloseHandle($proc); exit 1 }
>> "%PS_SCRIPT%" echo [Injector]::CloseHandle($proc)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
set "PS_EXIT=%errorlevel%"
del /f /q "%PS_SCRIPT%" >NUL 2>&1
if not "%PS_EXIT%"=="0" (
    echo.
    echo [ERREUR] L'injection a echoue ^(code %PS_EXIT%^) !
    pause
    exit /b 1
)

echo.
echo ===========================================
echo    INJECTION COMPLETE !
echo ===========================================
echo.
echo [1] VMP DLL injectee
echo [2] WhipClient DLL injectee
echo.
pause
exit /b 0

REM ─── Subroutine : cherche javaw.exe (Lunar) puis java.exe filtre par .menoria
REM     Trouve  -> goto :found_pid (saute directement au code principal)
REM     Non trouve -> goto :eof  (retour a l'appelant)
:search_client
for /f "tokens=2 delims=," %%i in ('tasklist /FI "IMAGENAME eq %PROCESS_NAME%" /FO csv /NH 2^>NUL') do (
    set "PID=%%~i"
    set "FOUND_PROC=%PROCESS_NAME%"
    goto :found_pid
)
set "MENORIA_PID_FILE=%TEMP%\whip_menoria_pid_%RANDOM%.txt"
powershell -NoProfile -Command "Get-Process -Name java -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*menoria*' -or -not $_.Path } | Select-Object -First 1 -ExpandProperty Id | Out-File -Encoding ascii -NoNewline '%MENORIA_PID_FILE%'" 2>NUL
if exist "%MENORIA_PID_FILE%" (
    for /f "usebackq tokens=*" %%p in ("%MENORIA_PID_FILE%") do (
        if not "%%p"=="" (
            set "PID=%%p"
            set "FOUND_PROC=%FALLBACK_PROCESS% (Menoria)"
            del /f /q "%MENORIA_PID_FILE%" >NUL 2>&1
            goto :found_pid
        )
    )
    del /f /q "%MENORIA_PID_FILE%" >NUL 2>&1
)
goto :eof
