BINARY := moonveil
ALIAS := mvl
LINUX_TARGET := x86_64-unknown-linux-musl

.PHONY: build build-linux test lint fmt install uninstall demo clean

build:
	cargo build --release

build-linux:
	cargo build --release --target $(LINUX_TARGET)

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

install:
	bash ./scripts/install.sh

uninstall:
	bash ./scripts/uninstall.sh

demo:
	cargo run -- --demo

clean:
	cargo clean
