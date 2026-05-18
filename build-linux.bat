@echo off
setlocal

REM ===== 目标三元组 =====
REM 通用动态链接（glibc）: x86_64-unknown-linux-gnu
REM 静态链接（musl，部署不挑系统）: x86_64-unknown-linux-musl
set TARGET=x86_64-unknown-linux-musl

REM ===== 检查 cargo-zigbuild =====
where cargo-zigbuild >nul 2>&1
if errorlevel 1 (
    echo [!] cargo-zigbuild 未安装，正在安装...
    cargo install --locked cargo-zigbuild
    if errorlevel 1 (
        echo [x] cargo-zigbuild 安装失败
        exit /b 1
    )
)

REM ===== 检查 rustup target =====
rustup target list --installed | findstr /B /C:"%TARGET%" >nul
if errorlevel 1 (
    echo [!] 添加 rustup target: %TARGET%
    rustup target add %TARGET%
    if errorlevel 1 (
        echo [x] target 添加失败
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
echo [OK] 产物: target\%TARGET%\release\ipv6-pool-proxy
endlocal
