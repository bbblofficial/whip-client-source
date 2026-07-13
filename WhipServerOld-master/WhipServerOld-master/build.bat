@echo off
echo ===============================================
echo Building AuthenticationServer on Linux (WSL)
echo ===============================================

wsl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERREUR: WSL n'est pas installé ou pas disponible
    echo Installez WSL avec: wsl --install -d Ubuntu
    pause
    exit /b 1
)

set "CURRENT_DIR=%~dp0"
set "WSL_PATH=/mnt/c%CURRENT_DIR:C:=%"
set "WSL_PATH=%WSL_PATH:\=/%"

echo Chemin Windows: %CURRENT_DIR%
echo Chemin WSL: %WSL_PATH%

echo Préparation du build...
if exist "build-linux" rmdir /s /q "build-linux"
mkdir build-linux

echo Compilation en cours...
wsl bash -c "cd '%WSL_PATH%' && cd build-linux && cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release"
if %errorlevel% neq 0 (
    echo ERREUR: Configuration CMake échouée
    pause
    exit /b 1
)

wsl bash -c "cd '%WSL_PATH%/build-linux' && ninja"
if %errorlevel% neq 0 (
    echo ERREUR: Compilation échouée
    pause
    exit /b 1
)

echo ===============================================
echo Compilation réussie !
echo Exécutable: build-linux/auth_server
echo ===============================================