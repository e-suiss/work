#!/bin/sh
# T-56, T-101
set -eu

: "${SOFTHSM_TOKEN_LABEL:?}" "${SOFTHSM_USER_PIN:?}" "${WORK_PEP_CERTIFICATE:?}"

module=/usr/lib/softhsm/libsofthsm2.so
label=work-access-pep
token() {
    pkcs11-tool --module "$module" --token-label "$SOFTHSM_TOKEN_LABEL" --login --pin "$SOFTHSM_USER_PIN" "$@"
}

openssl x509 -in "$WORK_PEP_CERTIFICATE" -outform DER -out /tmp/work-pep.der
token --read-object --type pubkey --label "$label" --output-file /tmp/key.out >/dev/null
if [ "$(head -c 10 /tmp/key.out)" = "-----BEGIN" ]; then
    openssl pkey -pubin -in /tmp/key.out -outform DER -out /tmp/key.der
else
    cp /tmp/key.out /tmp/key.der
fi
if ! openssl x509 -in /tmp/work-pep.der -inform DER -noout -pubkey | openssl pkey -pubin -outform DER | cmp -s - /tmp/key.der; then
    echo "work-access-pep: $WORK_PEP_CERTIFICATE is not of the token key $label" >&2
    exit 1
fi

if token --read-object --type cert --label "$label" --output-file /tmp/held.der >/dev/null 2>&1 \
    && cmp -s /tmp/held.der /tmp/work-pep.der; then
    echo "work-access-pep: certificate kept"
    exit 0
fi
while token --list-objects --type cert | grep -q "label:[[:space:]]*$label[[:space:]]*$"; do
    token --delete-object --type cert --label "$label" >/dev/null
done
token --write-object /tmp/work-pep.der --type cert --label "$label" >/dev/null
echo "work-access-pep: certificate written"
