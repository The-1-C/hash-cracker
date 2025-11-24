@echo off
echo Checking for Rust installation...
cargo --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Rust is NOT installed.
    echo Please install Rust from https://rustup.rs/ and try again.
    pause
    exit /b
)

echo Rust is installed.
echo Building Rust Cracker...
cd rust_cracker
cargo build --release
cd ..
echo.
echo Setup complete! You can now run 'run_cracker.bat' or 'generate_rainbow.bat'.
pause
