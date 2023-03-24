# Copyright (C) Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0
export RUST_LOG ?= info,cargo_tarpaulin=off
.PHONY: check
check:
	RUSTLFAGS='-Dwarnings' cargo check --all-features --all-targets

.PHONY: lint
lint:
	cargo clippy --all-features --all-targets -- --deny warnings
	cargo fmt -- --check
	RUSTDOCFLAGS='-Dwarnings' cargo doc --no-deps
	reuse lint

.PHONY: test
test:
	cargo test --all-features

.PHONY: tarpaulin
tarpaulin:
	cargo tarpaulin --all-features -o Html -o Xml

.PHONY: ci
ci: check lint test
