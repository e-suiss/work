# OP-33, OP-46, T-41
ARG GO_IMAGE=golang@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e
ARG RUNTIME_IMAGE=debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

FROM ${GO_IMAGE} AS build
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-trimpath
RUN GOBIN=/opt/litewitness go install filippo.io/torchwood/cmd/litewitness@v0.10.0 \
 && GOBIN=/opt/litewitness go install filippo.io/torchwood/cmd/witnessctl@v0.10.0

FROM ${RUNTIME_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
 && mkdir -p /var/lib/litewitness /run/litewitness /run/litewitness-public \
 && chown 65532:65532 /var/lib/litewitness /run/litewitness /run/litewitness-public
COPY --from=build /opt/litewitness/litewitness /opt/litewitness/witnessctl /usr/local/bin/
COPY --chmod=0755 entrypoint.sh /usr/local/bin/witness-entrypoint
USER 65532:65532
EXPOSE 7380
ENTRYPOINT ["/usr/local/bin/witness-entrypoint"]
