# OP-32, T-41
FROM debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update \
 && apt-get install -y --no-install-recommends chrony \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=0444 pki/server.pem /etc/chrony/nts/server.pem
COPY --chmod=0444 pki/server-test-only.key /etc/chrony/nts/server.key

USER 65532:65532
ENTRYPOINT ["chronyd", "-d", "-x", "-U"]
