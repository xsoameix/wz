@echo off

set argc=0
for %%x in (%*) do set /A argc+=1

if %argc% geq 3 (
  goto :usage
)
if %argc% leq 0 (
  goto :usage
)
if %argc% == 1 (
  set "action="
  set msvc=%1
)
if %argc% == 2 (
  set action=%1
  set msvc=%2
)

rem Get action
if not [%action%] == [] (
  if not "%action%" == "all" (
    goto :usage
  )
)

rem Get visual studio version
if %msvc% == "Visual Studio 2013" (
  set msvc_ver=12
)
if %msvc% == "Visual Studio 2015" (
  set msvc_ver=14
)
if not defined msvc_ver (
  goto :usage
)

rem Prepare the environment
if "%PROCESSOR_ARCHITECTURE%" == "x86" (
  call "C:\Program Files\Microsoft Visual Studio %msvc_ver%.0\VC\vcvarsall.bat"
) else (
  call "C:\Program Files (x86)\Microsoft Visual Studio %msvc_ver%.0\VC\vcvarsall.bat"
)

rem Set visual studio name
set msvc_name="Visual Studio %msvc_ver%"

rem Get wz folder
set wz=%cd%
cd ..

rem Get root folder
set root=%cd%
set zlib=%root%\zlib
set check=%root%\check

if "%action%" == "all" (
  rem Compile zlib
  cd "%zlib%"
  if not exist local mkdir local
  if not exist build mkdir build
  cd build
  cmake ^
    -DCMAKE_INSTALL_PREFIX="%zlib%\local" ^
    -G %msvc_name% ..
  msbuild INSTALL.vcxproj

  rem Compile check
  cd "%check%"
  if not exist local mkdir local
  cmake ^
    -DCMAKE_INSTALL_PREFIX="%check%\local" ^
    -G %msvc_name% .
  msbuild INSTALL.vcxproj
)

rem Compile wz
cd "%wz%"
if not exist local mkdir local
if not exist build mkdir build
cd build
cmake ^
  -DCMAKE_INSTALL_PREFIX="%wz%\local" ^
  -DZLIB_ROOT="%zlib%\local" ^
  -DCHECK_ROOT_DIR="%check%\local" ^
  -G %msvc_name% ..
msbuild INSTALL.vcxproj

rem Run Unit Tests
msbuild RUN_TESTS.vcxproj

rem Quit
cd ..
exit /B 0

rem Show usage
:usage
echo Usage: make [ACTION] VERSION
echo.
echo ACTION can be all or just empty
echo   all means building the dependencies and this project
echo   empty means building this project only
echo.
echo   eg: make all "Visual Studio 2013"
echo       make "Visual Studio 2015"
echo.
echo VERSION can be any one in following list:
echo   1. "Visual Studio 2013"
echo   2. "Visual Studio 2015"
exit /B 0
