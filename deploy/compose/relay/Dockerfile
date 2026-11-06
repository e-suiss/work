# T-51, T-56, T-41, MD-3
FROM ghcr.io/e-suiss/relay@sha256:7022a7677b4ebc0b5d9017591303f02a3c73df441c812d87946b6b816118ccac

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc curl jq socat \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > /etc/relay-softhsm2.conf \
 && chmod 0644 /etc/relay-softhsm2.conf \
 && chown 65532:65532 /var/lib/softhsm/tokens \
 && chmod 0700 /var/lib/softhsm/tokens \
 && install -d -o 65532 -g 65532 -m 0755 /var/lib/relay-access /run/relay-access /run/relay-trust

COPY --chmod=0755 keys.sh /usr/local/bin/relay-keys
COPY --chmod=0755 init.sh /usr/local/bin/relay-init
COPY --chmod=0755 start.sh /usr/local/bin/relay-start

ENV SOFTHSM2_CONF=/etc/relay-softhsm2.conf
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/relay-start"]
