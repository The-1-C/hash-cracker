@echo off
echo Starting Infinite Rainbow Generator...
echo Press Ctrl+C to stop.
cd rust_cracker
cargo run --release --bin generate
cd ..
pause
