@echo off
@rem builds the whole DES shell: modules A + B + C + D
setlocal
set "DIR=%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [build] Cannot find Visual Studio C++ tools.
  exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars32.bat" >nul

pushd "%DIR%"

echo ========================================================
echo Compiling Assembly Modules (A, B, C, D)...
echo ========================================================

ml /nologo /c /coff /Zi /I C:\Irvine /I . Test_ModuleA.asm
if errorlevel 1 goto :err
ml /nologo /c /coff /Zi /I C:\Irvine /I . moduleB5.asm
if errorlevel 1 goto :err
ml /nologo /c /coff /Zi /I C:\Irvine /I . ModuleC.asm
if errorlevel 1 goto :err
ml /nologo /c /coff /Zi /I C:\Irvine /I . moduleD.asm
if errorlevel 1 goto :err

echo ========================================================
echo Linking into DES_Shell.exe directly...
echo ========================================================

link /nologo /SUBSYSTEM:CONSOLE /DEBUG /OUT:DES_Shell.exe Test_ModuleA.obj moduleB5.obj ModuleC.obj moduleD.obj C:\Irvine\Irvine32.lib C:\Irvine\Kernel32.lib C:\Irvine\User32.lib /LIBPATH:C:\Irvine
if errorlevel 1 goto :err

echo.
echo [build] OK -^> DES_Shell.exe has been updated successfully!
echo.
popd
pause
exit /b 0

:err
echo.
echo [build] FAILED! Check assembler/linker errors above.
echo.
popd
pause
exit /b 1