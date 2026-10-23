# T-41

set shell := ["bash", "-euo", "pipefail", "-c"]

# T-31, T-5
kernel_targets := "wasm32-unknown-unknown thumbv7em-none-eabihf"

compose := "docker compose -f deploy/compose/compose.yaml"
dev_db_password := "local-only-not-a-secret"

default:
    @just --list

# T-41
check: fmt-check lint rules vectors squawk deny vet semgrep web-check cddl compose-check

# T-37
test:
    cargo nextest run --workspace --locked --no-tests=pass
    cargo test --workspace --locked --doc

test-full:
    cargo nextest run --workspace --locked --no-tests=pass --run-ignored all
    cargo test --workspace --locked --doc

# T-36, T-37
test-containers:
    cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=containers)'

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# T-33
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# T-31, T-46, T-52
rules:
    cargo fetch --locked
    cargo xtask check

# T-38
deny:
    cargo deny --locked check

vet:
    cargo vet --locked

audit:
    cargo audit

semgrep_version := "1.179.0"

# T-52, T-60
semgrep:
    if command -v semgrep > /dev/null; then sg=(semgrep); else sg=(uvx --from "semgrep=={{semgrep_version}}" semgrep); fi; \
    "${sg[@]}" --test --config .semgrep/rules.yml .semgrep/rules.rs; \
    "${sg[@]}" scan --config .semgrep/ --error --metrics=off

# T-36, T-52
squawk:
    files="$(find crates -path '*/migrations/*.sql' 2>/dev/null)"; \
    if ! command -v squawk > /dev/null; then \
      if [ -z "$files" ]; then echo "squawk not installed and no migrations yet; skipping"; exit 0; fi; \
      echo "squawk 2.68.0 required: https://github.com/sbdchd/squawk/releases/tag/v2.68.0" >&2; exit 1; \
    fi; \
    if squawk crates/store/fixtures/squawk-unsafe.sql > /dev/null; then echo "squawk accepted the unsafe fixture" >&2; exit 1; fi; \
    if [ -z "$files" ]; then echo "no migrations yet"; else squawk $files; fi

# T-31
cross:
    for t in {{kernel_targets}}; do cargo build --locked -p esuiss-work-kernel --target "$t"; done

# T-5, T-58
wasm:
    want="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"; \
    have="$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2)"; \
    if [ "$have" != "$want" ]; then echo "wasm-bindgen-cli $want required (found '${have:-none}'): cargo install wasm-bindgen-cli --version $want --locked" >&2; exit 1; fi
    cargo build --locked --release --target wasm32-unknown-unknown -p work-kernel-wasm
    wasm-bindgen --target web --out-dir packages/kernel/wasm target/wasm32-unknown-unknown/release/work_kernel_wasm.wasm

# T-5
ffi_lib := "target/debug/libwork_kernel_ffi." + if os() == "macos" { "dylib" } else { "so" }

uniffi-bindgen language:
    cargo build --locked -p work-kernel-ffi
    cargo run --locked -q -p work-kernel-ffi --features cli --bin uniffi-bindgen -- \
      generate --library {{ffi_lib}} --language {{language}} --no-format --out-dir target/uniffi/{{language}}

bindings-swift: (uniffi-bindgen "swift")

bindings-kotlin: (uniffi-bindgen "kotlin")

# T-5, T-37
test-swift: bindings-swift
    swiftc -swift-version 6 -warnings-as-errors \
      -Xcc -fmodule-map-file=target/uniffi/swift/work_kernel_ffiFFI.modulemap -I target/uniffi/swift \
      -L target/debug -lwork_kernel_ffi -Xlinker -rpath -Xlinker "{{justfile_directory()}}/target/debug" \
      target/uniffi/swift/work_kernel_ffi.swift sdks/bindings/uniffi/tests/swift/main.swift \
      -o target/uniffi/swift/kernel-vectors
    target/uniffi/swift/kernel-vectors conformance/vectors/kernel conformance/vectors/records sdks/bindings/core/tests/fixtures

# T-58
npm_packages := "packages/kernel"

# T-58, T-60
web-install:
    for p in {{npm_packages}}; do (cd "$p" && npm ci); done

# T-38, T-58
web-audit:
    for p in {{npm_packages}}; do (cd "$p" && npm audit --audit-level=high); done

# T-34, T-58
web-check: wasm
    for p in {{npm_packages}}; do (cd "$p" && npm run lint && npm run typecheck && npm run format:check && npm run build); done

# T-5, T-37
web-test: wasm
    cd packages/kernel && npm test

# T-5, T-37
web-e2e: wasm
    cd packages/kernel && npm run e2e

# T-41, T-51
compose-check:
    {{compose}} config -q

# T-46
catalog:
    cargo xtask catalog

# T-50
spec-counterparts *args:
    cargo xtask spec-counterparts {{args}}

# T-41, T-51, T-56, T-57
dev:
    {{compose}} up --detach --build --wait
    @echo "PostgreSQL     postgres://work_app@127.0.0.1:${WORK_DEV_PG_PORT:-5442}/work"
    @echo "NATS           nats://work@127.0.0.1:${WORK_DEV_NATS_PORT:-4232}  (monitor http://127.0.0.1:${WORK_DEV_NATS_MONITOR_PORT:-8232})"
    @echo "SoftHSM        PKCS#11 token 'work-dev': just dev-hsm --show-slots"
    @echo "Grafana        http://127.0.0.1:${WORK_DEV_GRAFANA_PORT:-3310}  (user admin, password local-only-not-a-secret)"
    @echo "Jaeger         http://127.0.0.1:${WORK_DEV_JAEGER_UI_PORT:-16696}   Prometheus http://127.0.0.1:${WORK_DEV_PROMETHEUS_PORT:-9099}"
    @echo "OTLP           127.0.0.1:${WORK_DEV_OTLP_GRPC_PORT:-4327} (gRPC), 127.0.0.1:${WORK_DEV_OTLP_HTTP_PORT:-4328} (HTTP)"
    @echo "Access         http://127.0.0.1:${WORK_DEV_ACCESS_PORT:-8180}  (Mailpit http://127.0.0.1:${WORK_DEV_MAIL_UI_PORT:-8035})"
    @echo "Relay          http://127.0.0.1:${WORK_DEV_RELAY_PORT:-4010}"

dev-down:
    {{compose}} down

dev-status:
    {{compose}} ps

dev-hsm *args:
    {{compose}} exec softhsm softhsm2-util {{args}}

# T-41
db-reset:
    {{compose}} rm --stop --force relay relay-migrate access postgres
    docker volume rm --force work-dev_pgdata
    just dev
    just db-seed

db-seed:
    for f in deploy/compose/postgres/seed/*.sql; do \
      [ -e "$f" ] || continue; echo "seed: $f"; \
      {{compose}} exec -T -e PGPASSWORD={{dev_db_password}} postgres \
        psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U work_app -d work < "$f"; \
    done

psql:
    {{compose}} exec -e PGPASSWORD={{dev_db_password}} postgres psql -h 127.0.0.1 -U work_app -d work

run:
    cargo run --locked -p work-server

image tag="work-server:local":
    docker build -f deploy/docker/Dockerfile -t {{tag}} .

# T-44, T-62
bench *args:
    cargo bench --locked -p esuiss-work-kernel --bench kernel_wallclock -- {{args}}

# T-44
wasm-size:
    CARGO_PROFILE_RELEASE_DEBUG=false CARGO_PROFILE_RELEASE_STRIP=true \
      cargo build --locked --release --target wasm32-unknown-unknown --target-dir target/wasm-size -p work-kernel-wasm
    f=target/wasm-size/wasm32-unknown-unknown/release/work_kernel_wasm.wasm; \
    echo "work_kernel_wasm.wasm: $(wc -c < "$f" | tr -d ' ') bytes, $(gzip -9 -c "$f" | wc -c | tr -d ' ') bytes gzip -9"

# T-44
wasm-startup: wasm
    cd packages/kernel && npm run startup
    cd packages/kernel && npm run e2e -- --grep t_44 --workers=1

bench-instructions *args:
    cargo bench --locked -p esuiss-work-kernel --bench kernel_instructions -- {{args}}

# T-44
profile *args:
    cargo flamegraph --root --bench kernel_wallclock -p esuiss-work-kernel -- --bench {{args}}

# T-37
mutants *args:
    cargo mutants --package esuiss-work-kernel --test-tool nextest {{args}}

# T-37, T-44
load script="smoke" *args:
    docker run --rm --network host -v "{{justfile_directory()}}/load:/load:ro" grafana/k6@sha256:3ddc8b1a33a2c3d8edc6e99b6a762ae36cba08788463458f5e6a7703e14eb77d run {{args}} /load/{{script}}.js

fuzz_toolchain := "nightly-2026-10-01"

# T-37
fuzz target="smoke" *args:
    cargo +{{fuzz_toolchain}} fuzz run --fuzz-dir fuzz {{target}} -- {{args}}

# T-59, T-38
release-build target:
    rm -rf target/vendor && mkdir -p target
    cargo vendor --locked --versioned-dirs target/vendor > target/vendor-config.toml
    if find target/vendor -type d \( -name .vscode -o -name .devcontainer -o -name .githooks -o -name .idea \) | grep .; then echo "vendored IDE/hook directories found (T-60)" >&2; exit 1; fi
    RUSTFLAGS="--remap-path-prefix={{justfile_directory()}}=/work --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
      cargo auditable build --locked --offline --config "{{justfile_directory()}}/target/vendor-config.toml" --release -p work-server -p work-signer -p work-cli --target {{target}}

release_bins := "work-server work-signer work-cli"

# T-5, T-38
release-ffi target:
    RUSTFLAGS="--remap-path-prefix={{justfile_directory()}}=/work --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
      cargo auditable build --locked --release -p work-kernel-ffi --target {{target}}

# T-38
sbom target out:
    mkdir -p {{out}}
    cargo cyclonedx --format json --spec-version 1.5 --target {{target}}
    for b in {{release_bins}}; do mv "bins/$b/$b.cdx.json" "{{out}}/$b.cdx.json"; done
    find bins crates xtask -name '*.cdx.json' -not -path '*/target/*' -delete
    for b in {{release_bins}}; do syft scan "file:target/{{target}}/release/$b" -o "spdx-json={{out}}/$b.spdx.json"; done

# T-40
changelog:
    git cliff --output CHANGELOG.md

# T-41
gen:
    cargo xtask check generated

record_vectors := "conformance/vectors/records"

# P-11 P-72
vectors:
    rm -rf target/vectors/records
    python3 {{record_vectors}}/gen/gen.py target/vectors/records
    if ! diff -r -x README.md -x gen {{record_vectors}} target/vectors/records; then echo "record vectors are stale: just vectors-write" >&2; exit 1; fi

vectors-write:
    python3 {{record_vectors}}/gen/gen.py {{record_vectors}}

# P-11 P-72
cddl:
    #!/usr/bin/env bash
    set -euo pipefail
    gemfile=.github/cddl/Gemfile
    if [ -n "${CDDL:-}" ]; then cddl=("$CDDL")
    elif BUNDLE_GEMFILE="$gemfile" bundle check > /dev/null 2>&1; then cddl=(env BUNDLE_GEMFILE="$gemfile" bundle exec cddl)
    elif command -v cddl > /dev/null && cddl 2>&1 | grep -q 'version 0.12.14$'; then cddl=(cddl)
    else
      echo "cddl gem 0.12.14 not found; skipping CDDL validation. Install the pinned gems with:"
      echo "  BUNDLE_GEMFILE=$gemfile bundle install"
      echo "or: gem install cddl -v 0.12.14 && gem install pstore -v 0.2.1 && gem install base64 -v 0.3.0 && gem install bigdecimal -v 4.1.3 (Ruby 4 no longer bundles pstore, base64, bigdecimal)"
      exit 0
    fi
    dir=target/vectors/cddl
    rm -rf "$dir"
    python3 {{record_vectors}}/gen/gen.py "$dir/json" "$dir/cbor"
    bad=0
    while read -r root name want; do
      schema="$dir/$root.cddl"
      [ -e "$schema" ] || { printf 'root = %s\n' "$root"; cat conformance/cddl/work-record.cddl; } > "$schema"
      if out="$("${cddl[@]}" "$schema" validate "$dir/cbor/$name.cbor" < /dev/null 2>&1)"; then got=pass; else got=fail; fi
      if [ "$got" != "$want" ]; then echo "$name: CDDL $got, expected $want"; grep -v 'Unused rule' <<< "$out" | head -20; bad=1; fi
    done < "$dir/cbor/manifest"
    [ "$bad" = 0 ] && echo "CDDL: $(wc -l < "$dir/cbor/manifest" | tr -d ' ') vectors match their cddl expectation"
    exit "$bad"
