cargo clean
@if ERRORLEVEL 1 goto :error
cargo install cargo-audit
@if ERRORLEVEL 1 goto :error
cargo install cargo-auditable
@if ERRORLEVEL 1 goto :error
cargo build --package letmein
@if ERRORLEVEL 1 goto :error
cargo test --package letmein
@if ERRORLEVEL 1 goto :error
cargo test --package letmein-conf
@if ERRORLEVEL 1 goto :error
cargo test --package letmein-proto
@if ERRORLEVEL 1 goto :error
cargo auditable build --release --package letmein
@if ERRORLEVEL 1 goto :error
cargo audit bin --deny warnings target\release\letmein.exe
@if ERRORLEVEL 1 goto :error
@echo SUCCESS
@pause
@exit /B 0

@:error
@pause
@exit /B 1
