@echo off
setlocal enabledelayedexpansion

REM --- Configuration Variables ---
REM !!! IMPORTANT: Change passwords and ensure they match NodeStarter.java !!!
set KEY_PASS=changeit
set STORE_PASS=changeit
set TRUST_PASS=changeit

REM Directory Structure
set CONFIG_DIR=config
set KEYSTORE_DIR=%CONFIG_DIR%\keystores
set TRUSTSTORE_DIR=%CONFIG_DIR%\truststore
set TRUSTSTORE_FILE=%TRUSTSTORE_DIR%\cacerts.jks

REM Port List File
set PORT_LIST_FILE=etc\portList.cfg

REM Certificate Validity (days)
set VALIDITY=3650

REM Distinguished Name Template
set DN_TEMPLATE="OU=Blockchain,O=D208,L=City,ST=State,C=CN"

REM --- Check for keytool ---
where keytool >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: keytool not found. Check JDK installation and PATH.
    goto :eof
)

REM --- Check for port list file ---
if not exist "%PORT_LIST_FILE%" (
    echo ERROR: Port list file not found: %PORT_LIST_FILE%
    goto :eof
)

REM --- Create Directories ---
echo Creating directories...
if not exist "%KEYSTORE_DIR%" mkdir "%KEYSTORE_DIR%"
if not exist "%TRUSTSTORE_DIR%" mkdir "%TRUSTSTORE_DIR%"

REM --- Clean Up Old Files ---
echo Cleaning up old files...
del /Q "%KEYSTORE_DIR%\node*.jks" > nul 2>&1
del /Q "%TRUSTSTORE_FILE%" > nul 2>&1
del /Q "temp_cert_*.cer" > nul 2>&1

REM --- Process Ports ---
echo Reading ports from %PORT_LIST_FILE%...
set PORTS=
set TEMP_CERT_FILES=

REM Read ports using for /f (ensure file exists from check above)
for /f "tokens=1" %%P in ('type "%PORT_LIST_FILE%" ^| findstr /R /C:"^[0-9][0-9]*"') do (
    set PORT=%%P
    set KEYSTORE_FILE=%KEYSTORE_DIR%\node!PORT!.jks
    set ALIAS=node!PORT!
    set CERT_FILE=temp_cert_!PORT!.cer
    set TEMP_CERT_FILES=!TEMP_CERT_FILES! "!CERT_FILE!"

    echo --- Generating for Port !PORT! ---
    echo Keystore: !KEYSTORE_FILE!

    REM Generate Keystore
    keytool -genkeypair -alias "!ALIAS!" -keyalg EC -keysize 256 ^
            -keystore "!KEYSTORE_FILE!" ^
            -storepass "%STORE_PASS%" -keypass "%KEY_PASS%" ^
            -validity "%VALIDITY%" ^
            -dname "CN=!ALIAS!,%DN_TEMPLATE%" ^
            -ext SAN=dns:localhost,ip:127.0.0.1

    if errorlevel 1 (
        echo ERROR: Failed generating keystore for port !PORT!.
        goto cleanup_and_exit
    )

    REM Export Certificate
    echo Exporting certificate to !CERT_FILE!...
    keytool -exportcert -alias "!ALIAS!" -keystore "!KEYSTORE_FILE!" ^
            -storepass "%STORE_PASS%" -file "!CERT_FILE!"

     if errorlevel 1 (
        echo ERROR: Failed exporting certificate for port !PORT!.
        goto cleanup_and_exit
    )
    set PORTS=!PORTS! !PORT!
)

if not defined PORTS (
    echo ERROR: No valid ports found in %PORT_LIST_FILE%.
    goto :eof
)

echo Ports to process:%PORTS%

REM --- Create/Update Truststore ---
echo -----------------------------------------------------
echo Creating/Updating Truststore: %TRUSTSTORE_FILE%
echo -----------------------------------------------------

REM 尝试在导入前显式创建一个空的（或几乎空的）keystore 文件
REM 这可能不是必需的，但可以帮助排除首次创建的问题
REM 我们用一个临时的密钥对生成它，然后可以删除那个临时条目，或者就让它留着
echo Ensuring truststore file exists (or creating)...
keytool -genkeypair -alias "tempinit" -keystore "%TRUSTSTORE_FILE%" -storepass "%TRUST_PASS%" -keypass "%TRUST_PASS%" -dname "CN=init" -validity 1 > nul 2>&1
REM 删除临时条目 (可选，如果上一步成功)
keytool -delete -alias "tempinit" -keystore "%TRUSTSTORE_FILE%" -storepass "%TRUST_PASS%" > nul 2>&1

REM Import certificates into Truststore
for %%P in (%PORTS%) do (
    REM 构造完整的命令字符串用于调试输出
    set "IMPORT_CMD=keytool -importcert -alias "node%%P" -keystore "%TRUSTSTORE_FILE%" -storepass "%TRUST_PASS%" -file "temp_cert_%%P.cer" -noprompt"

    echo --- Importing cert for port %%P ---
    echo Command: !IMPORT_CMD!

    REM 执行命令 (放在单行，移除 ^)
    keytool -importcert -alias "node%%P" -keystore "%TRUSTSTORE_FILE%" -storepass "%TRUST_PASS%" -file "temp_cert_%%P.cer" -noprompt

    REM 立即检查错误级别
    if errorlevel 1 (
        echo ERROR: Failed importing certificate for port %%P. Check command output above.
        echo Truststore: %TRUSTSTORE_FILE%
        echo Cert file: temp_cert_%%P.cer
        goto cleanup_and_exit
    ) else (
        echo Successfully imported cert for port %%P.
    )
    echo. REM 添加空行增加可读性
)

REM --- Clean up temporary files ---
:cleanup
echo Cleaning up temporary files...
if defined TEMP_CERT_FILES (
    for %%F in (%TEMP_CERT_FILES%) do (
        del /Q %%F > nul 2>&1
    )
)
REM 可以选择是否删除用于初始化的临时 truststore (如果需要纯净的)
REM del /Q "%TRUSTSTORE_FILE%" > nul 2>&1

echo --- Done ---
goto :eof

:cleanup_and_exit
echo An error occurred. Cleaning up temporary files...
goto cleanup

:eof
endlocal