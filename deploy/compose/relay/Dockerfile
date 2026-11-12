# T-51, T-56, T-41, MD-3, E-91
FROM ghcr.io/e-suiss/relay@sha256:c4795d358bb71147701a68af290f40b2aba2a720e1839d547fb9824b660bf9e8

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc curl jq haproxy \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'directories.tokendir = /var/lib/relay-softhsm\nobjectstore.backend = file\nlog.level = ERROR\n' > /etc/relay-softhsm2.conf \
 && chmod 0644 /etc/relay-softhsm2.conf \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/relay-softhsm \
 && install -d -o 65532 -g 65532 -m 0755 /var/lib/relay-access /var/lib/relay-client /var/lib/relay-trust \
 && cp /etc/ssl/certs/ca-certificates.crt /etc/relay-system-ca.crt \
 && ln -sf /var/lib/relay-trust/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --chmod=0755 keys.sh /usr/local/bin/relay-keys
COPY --chmod=0755 init.sh /usr/local/bin/relay-init
COPY --chmod=0755 start.sh /usr/local/bin/relay-start
COPY --chmod=0755 register.sh /usr/local/bin/relay-register
COPY --chmod=0644 register.exs /usr/local/lib/relay-work/register.exs
COPY --chmod=0644 proxy.cfg /etc/relay-proxy.cfg

ENV SOFTHSM2_CONF=/etc/relay-softhsm2.conf
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/relay-start"]
