@echo off
setlocal

REM ===== Target triple =====
REM glibc dynamic: x86_64-unknown-linux-gnu
REM musl static  : x86_64-unknown-linux-musl
set TARGET=x86_64-unknown-linux-musl

REM ===== Check cargo-zigbuild =====
where cargo-zigbuild >nul 2>&1
if errorlevel 1 (
    echo [!] cargo-zigbuild not installed, installing...
    cargo install --locked cargo-zigbuild
    if errorlevel 1 (
        echo [x] Failed to install cargo-zigbuild
        exit /b 1
    )
)

REM ===== Check rustup target =====
rustup target list --installed | findstr /B /C:"%TARGET%" >nul
if errorlevel 1 (
    echo [!] Adding rustup target: %TARGET%
    rustup target add %TARGET%
    if errorlevel 1 (
        echo [x] Failed to add target
        exit /b 1
    )
)

echo.
echo === Building %TARGET% (release) ===
cargo zigbuild --release --target %TARGET%
if errorlevel 1 (
    echo.
    echo [x] Build FAILED
    exit /b 1
)

echo.
echo [OK] Output: target\%TARGET%\release\ipv6-pool-proxy
endlocal