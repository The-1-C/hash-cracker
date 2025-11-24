@echo off
echo Starting High-Speed Hash Cracker (Rust)...
cd rust_cracker
cargo run --release --bin rust_cracker
cd ..
pause
