# T-41, T-7, T-56, T-72, T-39

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
ARG SIGNER_IMAGE=debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG SERVER_IMAGE=gcr.io/distroless/cc-debian13@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

FROM ${RUST_IMAGE} AS build
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    SQLX_OFFLINE=true
COPY . .
RUN cargo build --locked --package work-server --package work-signer --package work-cli \
 && install -D -m 0755 target/debug/work-server /out/work-server \
 && install -D -m 0755 target/debug/work-signer /out/work-signer \
 && install -D -m 0755 target/debug/work-cli /out/work-cli

FROM ${SIGNER_IMAGE} AS signer
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --groups softhsm --no-create-home --shell /usr/sbin/nologin nonroot \
 && chown 65532:softhsm /var/lib/softhsm/tokens \
 && install -d -o 65532 -g 65532 -m 0700 /run/work-signer
COPY --from=build /out/work-signer /usr/local/bin/work-signer
COPY --chmod=0755 deploy/compose/work/signer-entrypoint.sh /usr/local/bin/work-signer-entrypoint
USER nonroot
ENTRYPOINT ["/usr/local/bin/work-signer-entrypoint"]

# T-56, T-101, T-102
FROM ${SIGNER_IMAGE} AS hsm
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/* \
 && for lib in /usr/lib/softhsm/libsofthsm2.so $(ldd /usr/lib/softhsm/libsofthsm2.so | awk '$2 == "=>" && $3 ~ /^\// {print $3}'); do \
      case "$(basename "$lib")" in \
        libc.so.*|libm.so.*|libgcc_s.so.*|libstdc++.so.*|ld-linux*) ;; \
        *) dir="/out$(dirname "$(readlink -f "$lib")")"; mkdir -p "$dir"; cp -L "$lib" "$dir/$(basename "$lib")" ;; \
      esac; \
    done \
 && install -D -m 0644 /etc/softhsm/softhsm2.conf /out/etc/softhsm/softhsm2.conf

# T-36, OP-28
FROM ${SIGNER_IMAGE} AS cli
COPY --from=build /out/work-cli /usr/local/bin/work-cli
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/work-cli"]

FROM ${SERVER_IMAGE} AS server
COPY --from=hsm /out/ /
COPY --from=build /out/work-server /usr/local/bin/work-server
USER 65532:65532
EXPOSE 8090 8091 8443
ENTRYPOINT ["/usr/local/bin/work-server"]
