SETLOCAL
SET BATCH_FILE_NAME=%0
SET BATCH_DIR_NAME=%0\..

for /f "usebackq tokens=*" %%i in (`"%BATCH_DIR_NAME%\..\submodules\IPA-DN-ThinLib\src\BuildFiles\Utility\vswhere.exe" -version [17.0^,18.0^) -sort -requires Microsoft.Component.MSBuild -find Common7\Tools\VsDevCmd.bat`) do (
    if exist "%%i" (
        call "%%i"
    )
)

echo on

del %BATCH_DIR_NAME%\bin\BuildRelease.exe

msbuild /target:Clean /property:Configuration=Debug "%BATCH_DIR_NAME%\BuildRelease\BuildRelease.csproj"
IF ERRORLEVEL 1 GOTO LABEL_ERROR

msbuild /target:Rebuild /property:Configuration=Debug "%BATCH_DIR_NAME%\BuildRelease\BuildRelease.csproj"
IF ERRORLEVEL 1 GOTO LABEL_ERROR

copy /y "%BATCH_DIR_NAME%\BuildRelease\bin\BuildReleaseTmp.exe" "%BATCH_DIR_NAME%\bin\BuildRelease.exe"
IF ERRORLEVEL 1 GOTO LABEL_ERROR

cmd /k "%BATCH_DIR_NAME%\bin\BuildRelease.exe /CMD:All %1"
IF ERRORLEVEL 1 GOTO LABEL_ERROR



:LABEL_ERROR



EXIT %ERRORLEVEL%

