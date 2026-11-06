# T-41, T-56
FROM debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update \
 && apt-get install -y --no-install-recommends jq softhsm2 opensc openssl xxd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --groups softhsm --no-create-home --shell /usr/sbin/nologin nonroot \
 && chown 65532:softhsm /var/lib/softhsm/tokens

COPY --chmod=0755 entrypoint.sh /usr/local/bin/softhsm-entrypoint
# T-56, T-101, T-103
COPY --chmod=0755 access-keys.sh /usr/local/bin/work-access-keys
# T-56, T-101
COPY --chmod=0755 access-pep.sh /usr/local/bin/work-access-pep
# T-56, T-102
COPY --chmod=0755 server-tls.sh /usr/local/bin/work-server-tls

USER nonroot
ENTRYPOINT ["/usr/local/bin/softhsm-entrypoint"]
