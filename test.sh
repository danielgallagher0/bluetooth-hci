#! /bin/sh

cargo test --all --no-default-features --features="version-5-0" && \
 cargo test --all --no-default-features --features="version-4-2" && \
  cargo test --all --no-default-features --features="version-4-1"