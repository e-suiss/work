# T-41

set shell := ["bash", "-euo", "pipefail", "-c"]

# T-31, T-5
kernel_targets := "wasm32-unknown-unknown thumbv7em-none-eabihf"

compose := "docker compose -f deploy/compose/compose.yaml"
dev_db_password := "local-only-not-a-secret"

default:
    @just --list

# T-41
check: fmt-check lint rules deny compose-check

# T-37
test:
    cargo nextest run --workspace --locked --no-tests=pass
    cargo test --workspace --locked --doc

test-full:
    cargo nextest run --workspace --locked --no-tests=pass --run-ignored all
    cargo test --workspace --locked --doc

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

# T-52
semgrep:
    semgrep --test --config .semgrep/rules.yml .semgrep/rules.rs
    semgrep scan --config .semgrep/ --error --metrics=off

# T-36, T-52
squawk:
    files="$(find crates -path '*/migrations/*.sql' 2>/dev/null)"; \
    if [ -z "$files" ]; then echo "no migrations yet"; else squawk $files; fi

# T-31
cross:
    for t in {{kernel_targets}}; do cargo build --locked -p esuiss-work-kernel --target "$t"; done

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
    @just dev-products

# T-51
dev-products:
    #!/usr/bin/env bash
    set -euo pipefail
    for product in access relay; do
        status="$(sed -n "/^\[$product\]/,/^\[/s/^status = \"\(.*\)\"/\1/p" compat.toml)"
        if [[ "$status" == published ]]; then
            {{compose}} --profile "$product" up --detach --wait
            echo "$product         started from compat.toml"
        else
            echo "$product         not published yet (compat.toml status: $status); the service stays off"
        fi
    done

dev-down:
    {{compose}} --profile access --profile relay down

dev-status:
    {{compose}} ps

dev-hsm *args:
    {{compose}} exec softhsm softhsm2-util {{args}}

# T-41
db-reset:
    {{compose}} rm --stop --force postgres
    docker volume rm --force work-dev_pgdata
    {{compose}} up --detach --wait postgres
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

# T-37
fuzz target="smoke" *args:
    cargo +nightly fuzz run --fuzz-dir fuzz {{target}} {{args}}

# T-59, T-38
release-build target:
    rm -rf target/vendor && mkdir -p target
    cargo vendor --locked --versioned-dirs target/vendor > target/vendor-config.toml
    if find target/vendor -type d \( -name .vscode -o -name .devcontainer -o -name .githooks -o -name .idea \) | grep .; then echo "vendored IDE/hook directories found (T-60)" >&2; exit 1; fi
    RUSTFLAGS="--remap-path-prefix={{justfile_directory()}}=/work --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
      cargo auditable build --locked --offline --config "{{justfile_directory()}}/target/vendor-config.toml" --release -p work-server -p work-signer -p work-cli --target {{target}}

# T-38
sbom target binary out:
    mkdir -p {{out}}
    cargo cyclonedx --manifest-path bins/work-server/Cargo.toml --format json --spec-version 1.5 --target {{target}}
    find bins crates xtask -name '*.cdx.json' -not -path '*/target/*' -exec mv {} {{out}}/ \;
    syft scan "file:{{binary}}" -o "spdx-json={{out}}/work-server.spdx.json"

# T-40
changelog:
    git cliff --output CHANGELOG.md

# T-41
gen:
    cargo xtask check generated
