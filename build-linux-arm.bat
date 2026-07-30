@echo off
setlocal EnableDelayedExpansion

REM ===== Target triple =====
REM ARMv8 Linux musl (static)
set TARGET=aarch64-unknown-linux-musl

REM ===== Locate rustup's bundled mingw (self-contained) =====
for /f "delims=" %%i in ('rustc --print sysroot') do set "RUST_SYSROOT=%%i"
set "RUST_MINGW=!RUST_SYSROOT!\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"

if not exist "!RUST_MINGW!\x86_64-w64-mingw32-gcc.exe" (
    echo [x] rust-mingw not found at !RUST_MINGW!
    echo     Run: rustup default stable-x86_64-pc-windows-gnu
    exit /b 1
)

REM ===== Sanitize PATH =====
set "PATH=!RUST_MINGW!;!PATH!"
set "PATH=!PATH:C:\TDM-GCC-64\bin;=!"
set "PATH=!PATH:;C:\TDM-GCC-64\bin=!"

REM ===== Host linker (Windows GNU host) =====
set "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=!RUST_MINGW!\x86_64-w64-mingw32-gcc.exe"

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

REM ===== Check rust target =====
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
