# OP-42, OP-43, T-41
ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
ARG RUNTIME_IMAGE=debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

FROM ${RUST_IMAGE} AS build
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never
RUN cargo install --locked roughenough-server --version =2.2.0 --root /opt/roughenough

FROM ${RUNTIME_IMAGE}
COPY --from=build /opt/roughenough/bin/roughenough_server /usr/local/bin/roughenough_server
COPY --chown=65532:65532 --chmod=0400 seeds/a-test-only.seed seeds/b-test-only.seed seeds/c-test-only.seed /etc/roughenough/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/roughenough_server"]
