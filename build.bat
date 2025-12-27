@echo off
setlocal

rem === 自动设置路径 ===
set CURDIR=%~dp0
set JAVA_FILE=HookApplication.java
set OUT_DIR=%CURDIR%out
set SDK=%ANDROID_SDK_ROOT%
if "%SDK%"=="" set SDK=%ANDROID_HOME%
set PLATFORM_JAR=%SDK%\platforms\android-28\android.jar

rem 自动找 d8
for /f "delims=" %%i in ('dir /b /ad "%SDK%\build-tools" ^| sort /r') do (
    if exist "%SDK%\build-tools\%%i\d8.bat" (
        set D8=%SDK%\build-tools\%%i\d8.bat
        goto found_d8
    )
)
:found_d8

if "%D8%"=="" (
    echo [错误] 未找到 d8.bat，請檢查 Android SDK 是否安装。
    pause
    exit /b
)

if not exist "%PLATFORM_JAR%" (
    echo [错误] 未找到 %PLATFORM_JAR%
    echo 请修改此脚本中的 PLATFORM_JAR 对应 API 版本
    pause
    exit /b
)

echo 当前目录: %CURDIR%
echo 使用 android.jar: %PLATFORM_JAR%
echo 使用 d8: %D8%

rem === 清理输出目录 ===
if exist "%OUT_DIR%" rd /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"
mkdir "%OUT_DIR%\classes"
mkdir "%OUT_DIR%\dex"

rem === 编译 Java ===
echo 编译 Java 源码中...
javac -encoding UTF-8 -source 1.8 -target 1.8 -bootclasspath "%PLATFORM_JAR%" -classpath "%PLATFORM_JAR%" -d "%OUT_DIR%\classes" "%JAVA_FILE%"
if errorlevel 1 (
    echo [错误] 编译失败！
    pause
    exit /b
)

rem === 打包为 jar ===
echo 打包为 JAR...
pushd "%OUT_DIR%\classes"
jar cf "%OUT_DIR%\hook.jar" .
popd

rem === 转换为 DEX ===
echo 转换为 DEX...
"%D8%" --min-api 21 --output "%OUT_DIR%\dex" --lib "%PLATFORM_JAR%" "%OUT_DIR%\hook.jar"

if exist "%OUT_DIR%\dex\classes.dex" (
    echo.
    echo ✅ 编译成功！
    echo 输出文件: %OUT_DIR%\dex\classes.dex

    if exist "%CURDIR%app\src\main\assets" (
        copy /y "%OUT_DIR%\dex\classes.dex" "%CURDIR%app\src\main\assets\classesx.dex" >nul
        echo 已同步到 assets: %CURDIR%app\src\main\assets\classesx.dex
    )
) else (
    echo ❌ 未生成 classes.dex，请检查输出。
)
pause
endlocal
