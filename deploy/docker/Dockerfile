# T-40, T-59

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

FROM ${RUST_IMAGE} AS chef
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="--remap-path-prefix=/src=/work --remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo install --locked cargo-chef --version 0.1.78

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --package work-server --package work-signer --package work-cli --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --package work-server --package work-signer --package work-cli

FROM ${RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="work" \
      org.opencontainers.image.source="https://github.com/e-suiss/work" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /src/target/release/work-server /usr/local/bin/work-server
COPY --from=builder /src/target/release/work-signer /usr/local/bin/work-signer
COPY --from=builder /src/target/release/work-cli /usr/local/bin/work-cli
ENV WORK_LISTEN=0.0.0.0:8090
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/work-server"]
