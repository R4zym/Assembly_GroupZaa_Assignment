@echo off
@rem Module D build helper
@rem Usage:  build_run.cmd Test_ModuleD.asm          (build + run)
@rem         build_run.cmd Test_ModuleD.asm --norun  (build only)
setlocal

set "NAME=%~n1"
if "%NAME%"=="" set "NAME=Test_ModuleD"
set "FILE=%~1"
if "%FILE%"=="" set "FILE=%NAME%.asm"
set "DIR=%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [build] Could not find Visual Studio C++ tools.
  exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars32.bat" >nul

pushd "%DIR%"
echo [build] Assembling %FILE%
ml /nologo /c /coff /Zi /I C:\Irvine "%FILE%"
if errorlevel 1 goto :err

echo [build] Linking %NAME%.exe
link /nologo /SUBSYSTEM:CONSOLE /DEBUG "%NAME%.obj" C:\Irvine\Irvine32.lib C:\Irvine\Kernel32.lib C:\Irvine\User32.lib /LIBPATH:C:\Irvine
if errorlevel 1 goto :err

echo [build] OK
popd

if "%~2"=="--norun" exit /b 0

echo.
"%DIR%%NAME%.exe"
exit /b 0

:err
echo [build] FAILED
popd
exit /b 1
