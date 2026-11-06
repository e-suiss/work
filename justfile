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
    cargo nextest run --workspace --locked --no-tests=pass --run-ignored all -E 'not (binary(=containers) | binary(=compose))'
    cargo test --workspace --locked --doc

# T-36, T-37, OP-33, OP-46
test-containers:
    docker build --quiet --tag work-dev/witness:local deploy/compose/witness
    cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=containers)'

# OP-32, OP-42, OP-43, T-41, T-96, T-101
test-compose:
    dir="$(mktemp -d)"; just dev-access "$dir"; \
    WORK_ACCESS_LOCAL="$dir" SOFTHSM2_CONF="$dir/softhsm2.conf" cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=compose) & not test(/^(signed|upkeep|status|retired|commit)::/)'

# T-103: disables Work's platform stream as its owner, for the CI job to check that work-server
# opens it again after a restart
test-compose-upkeep:
    dir="$(mktemp -d)"; just dev-access "$dir"; \
    WORK_ACCESS_LOCAL="$dir" SOFTHSM2_CONF="$dir/softhsm2.conf" cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=compose) & test(/^upkeep::/)'

# T-101, T-104, T-97: once Access's realms sign key lookups and tokens (waiting at most `wait`
# seconds), the signed key lookup, a real user token from Access's own client and one from
# Work's, and the reads work-server serves for it; `dir` keeps the token copy for
# `test-compose-only`
test-compose-signed dir wait="600":
    just dev-access "{{dir}}"
    WORK_ACCESS_LOCAL="{{dir}}" SOFTHSM2_CONF="{{dir}}/softhsm2.conf" WORK_ACCESS_SIGNED_WAIT_S="{{wait}}" cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=compose) & test(/^signed::wait_until_/)'
    {{compose}} run --rm --no-deps -T --entrypoint access-local-client access-bootstrap login --issuer "$(jq -er '.realms[] | select(.slug == "acme") | .issuer' "{{dir}}/bootstrap.json")" --ca /var/lib/access/certs/ca.crt --client-id "$(jq -er '.test_user.client_id' "{{dir}}/bootstrap.json")" --redirect-uri "$(jq -er '.test_user.redirect_uri' "{{dir}}/bootstrap.json")" --identifier "$(jq -er '.test_user.identifier' "{{dir}}/bootstrap.json")" --password-env BOOTSTRAP_TEST_PASSWORD --passkey access/bootstrap/test-user-passkey --device-key access/bootstrap/test-user-device --hsm-module /usr/lib/softhsm/libsofthsm2.so --hsm-token access-server --hsm-pin-file /var/lib/access/secrets/hsm-access-server --resource "$(jq -er '.clients[] | select(.product == "work") | .client_id' "{{dir}}/bootstrap.json")" > "{{dir}}/tool-login.json"
    WORK_ACCESS_LOCAL="{{dir}}" SOFTHSM2_CONF="{{dir}}/softhsm2.conf" cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=compose) & test(/^signed::/) & not test(/^signed::wait_until_/)'

# T-102, T-103: one compose test by its full name, over the token copy `test-compose-signed` left
# in `dir`
test-compose-only dir name:
    WORK_ACCESS_LOCAL="{{dir}}" SOFTHSM2_CONF="{{dir}}/softhsm2.conf" cargo nextest run --workspace --locked --no-tests=fail --run-ignored only -E 'binary(=compose) & test(={{name}})'

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

# T-36, T-52, OP-28
squawk:
    files="$(find crates -path '*/migrations/*.sql' 2>/dev/null | sort)"; \
    if ! command -v squawk > /dev/null; then \
      if [ -z "$files" ]; then echo "squawk not installed and no migrations yet; skipping"; exit 0; fi; \
      echo "squawk 2.68.0 required: https://github.com/sbdchd/squawk/releases/tag/v2.68.0" >&2; exit 1; \
    fi; \
    if squawk crates/store/fixtures/squawk-unsafe.sql > /dev/null; then echo "squawk accepted the unsafe fixture" >&2; exit 1; fi; \
    if squawk crates/store/fixtures/squawk-unsafe-index.sql > /dev/null; then echo "squawk accepted a blocking index on an existing table (OP-28)" >&2; exit 1; fi; \
    squawk --no-assume-in-transaction crates/store/fixtures/squawk-concurrent-index.sql; \
    if [ -z "$files" ]; then echo "no migrations yet"; exit 0; fi; \
    tx=(); notx=(); \
    for f in $files; do if [ "$(head -c 17 "$f")" = "-- no-transaction" ]; then notx+=("$f"); else tx+=("$f"); fi; done; \
    if [ "${#tx[@]}" -gt 0 ]; then squawk "${tx[@]}"; fi; \
    if [ "${#notx[@]}" -gt 0 ]; then squawk --no-assume-in-transaction "${notx[@]}"; fi

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
    target/uniffi/swift/kernel-vectors conformance/vectors/kernel conformance/vectors/records conformance/vectors/kernel conformance/vectors/restriction

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
    @echo "PostgreSQL     postgres://work_app@127.0.0.1:${WORK_DEV_PG_PORT:-5442}/work and /work_derived  (migrate: just dev-migrate)"
    @echo "NATS           nats://work@127.0.0.1:${WORK_DEV_NATS_PORT:-4232}  (monitor http://127.0.0.1:${WORK_DEV_NATS_MONITOR_PORT:-8232})"
    @echo "SoftHSM        PKCS#11 token 'work-dev': just dev-hsm --show-slots"
    @echo "S3             http://127.0.0.1:${WORK_DEV_S3_PORT:-7072}  (body store; access key work-dev)"
    @echo "Grafana        http://127.0.0.1:${WORK_DEV_GRAFANA_PORT:-3310}  (user admin, password local-only-not-a-secret)"
    @echo "Jaeger         http://127.0.0.1:${WORK_DEV_JAEGER_UI_PORT:-16696}   Prometheus http://127.0.0.1:${WORK_DEV_PROMETHEUS_PORT:-9099}"
    @echo "OTLP           127.0.0.1:${WORK_DEV_OTLP_GRPC_PORT:-4327} (gRPC), 127.0.0.1:${WORK_DEV_OTLP_HTTP_PORT:-4328} (HTTP)"
    @echo "Access         https://access-server:8443 on 127.0.0.1:8443  (CA, PEP certificate and bootstrap.json: just dev-access <dir>)"
    @echo "Relay          https://relay on 127.0.0.1:443, node http://127.0.0.1:${WORK_DEV_RELAY_PORT:-4010}"
    @echo "Witness        http://127.0.0.1:${WORK_DEV_WITNESS_PORT:-7390}  (litewitness, C2SP tlog-witness)"
    @echo "Work server    http://127.0.0.1:${WORK_DEV_SERVER_PORT:-8190}  (health http://127.0.0.1:${WORK_DEV_SERVER_INTERNAL_PORT:-8191}/readyz, signer socket in volume signer-socket)"

# T-96, T-101, T-103, T-56: Access's CA, bootstrap.json, Work's PEP certificate, a copy of the
# work-dev token that holds its key and of Access's token that holds the test user's passkey with
# its PIN, and a SoftHSM configuration for those copies
dev-access dir:
    mkdir -p "{{dir}}/tokens"
    {{compose}} exec -T access cat /var/lib/access/certs/ca.crt > "{{dir}}/ca.crt"
    {{compose}} exec -T access cat /var/lib/access/bootstrap/bootstrap.json > "{{dir}}/bootstrap.json"
    {{compose}} run --rm --no-deps -T --entrypoint cat work-access-pep /var/lib/access/product-tls/work-pep.crt > "{{dir}}/work-pep.crt"
    {{compose}} exec -T softhsm tar -C /var/lib/softhsm/tokens -cf - . | tar -C "{{dir}}/tokens" -xf -
    {{compose}} cp access:/var/lib/softhsm/tokens/. "{{dir}}/tokens/"
    {{compose}} exec -T access cat /var/lib/access/secrets/hsm-access-server > "{{dir}}/access-hsm-pin"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$(cd "{{dir}}/tokens" && pwd)" > "{{dir}}/softhsm2.conf"

dev-down:
    {{compose}} down

dev-status:
    {{compose}} ps

dev-hsm *args:
    {{compose}} exec softhsm softhsm2-util {{args}}

# T-36, OP-28: migrations are a separate step, never part of node start-up
dev-migrate:
    for c in canonical derived; do \
      PGHOST=127.0.0.1 PGPORT="${WORK_DEV_PG_PORT:-5442}" PGUSER=work_owner PGPASSWORD={{dev_db_password}} \
        cargo run --locked -q -p work-cli -- migrate "$c"; \
    done

# T-41
db-reset:
    {{compose}} rm --stop --force relay relay-init access work-postgres
    docker volume rm --force work-dev_pgdata
    just dev
    just dev-migrate
    just db-seed

db-seed:
    for f in deploy/compose/postgres/seed/*.sql; do \
      [ -e "$f" ] || continue; echo "seed: $f"; \
      {{compose}} exec -T -e PGPASSWORD={{dev_db_password}} work-postgres \
        psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U work_app -d work < "$f"; \
    done

psql:
    {{compose}} exec -e PGPASSWORD={{dev_db_password}} work-postgres psql -h 127.0.0.1 -U work_app -d work

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
    cw="$dir/compromise-window"
    mkdir -p "$cw"
    { printf 'root = compromise-window\n'; cat conformance/cddl/work-compromise-window.cddl; } > "$cw.cddl"
    python3 -I -c 'import json, pathlib, sys; v = json.loads(pathlib.Path(sys.argv[1]).read_text()); out = pathlib.Path(sys.argv[2]); [(out / (c["id"] + ".cbor")).write_bytes(bytes.fromhex(c["cbor"])) for c in v["cases"]]; (out / "manifest").write_text("".join(c["id"] + " " + ("pass" if c["valid"] else "fail") + "\n" for c in v["cases"]))' conformance/vectors/compromise-window/compromise-window.json "$cw"
    while read -r name want; do
      if out="$("${cddl[@]}" "$cw.cddl" validate "$cw/$name.cbor" < /dev/null 2>&1)"; then got=pass; else got=fail; fi
      if [ "$got" != "$want" ]; then echo "compromise-window/$name: CDDL $got, expected $want"; grep -v 'Unused rule' <<< "$out" | head -20; bad=1; fi
    done < "$cw/manifest"
    [ "$bad" = 0 ] && echo "CDDL: $(wc -l < "$cw/manifest" | tr -d ' ') compromise-window vectors match their cddl expectation"
    exit "$bad"

sqlx_db_port := "5499"
sqlx_db_url := "postgres://postgres:" + dev_db_password + "@127.0.0.1:" + sqlx_db_port + "/work"

# T-36
sqlx-db:
    #!/usr/bin/env bash
    set -euo pipefail
    image="$(sed -n 's/^ *image: \(postgres@sha256:[0-9a-f]*\).*$/\1/p' deploy/compose/compose.yaml | sort -u)"
    [ -n "$image" ] || { echo "no postgres pin in deploy/compose/compose.yaml" >&2; exit 1; }
    docker rm --force work-sqlx > /dev/null 2>&1 || true
    docker run --detach --name work-sqlx --env POSTGRES_PASSWORD={{dev_db_password}} \
      --publish 127.0.0.1:{{sqlx_db_port}}:5432 "$image" > /dev/null
    ready() { docker exec work-sqlx pg_isready -h 127.0.0.1 -U postgres -d postgres > /dev/null 2>&1; }
    for _ in $(seq 120); do ready && break; sleep 1; done
    ready || { docker logs work-sqlx >&2; exit 1; }
    run() { docker exec -i work-sqlx psql -X -q -v ON_ERROR_STOP=1 -U postgres "$@"; }
    run -d postgres -f - < crates/store/bootstrap/roles.sql
    run -d postgres -f - < crates/store/bootstrap/databases.sql
    run -d work -f - < crates/store/bootstrap/canonical.sql
    for f in crates/store/migrations/{foundation,canonical,derived}/*.sql; do
      run -1 -d work -f - < "$f"
    done
    echo "query database ready: every migration of both clusters in the one database work"

# T-36
sqlx-prepare:
    DATABASE_URL={{sqlx_db_url}} cargo sqlx prepare --workspace -- --locked --package work-store

# T-36
sqlx-check:
    DATABASE_URL={{sqlx_db_url}} cargo sqlx prepare --workspace --check -- --locked --package work-store
