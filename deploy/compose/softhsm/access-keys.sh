#!/bin/sh
# T-56, T-101, T-103
set -eu

: "${SOFTHSM_TOKEN_LABEL:?}" "${SOFTHSM_USER_PIN:?}" "${WORK_ACCESS_KEYS:?}"

module=/usr/lib/softhsm/libsofthsm2.so
token() {
    pkcs11-tool --module "$module" --token-label "$SOFTHSM_TOKEN_LABEL" --login --pin "$SOFTHSM_USER_PIN" "$@"
}

b64url() {
    base64 -w 0 | tr '+/' '-_' | tr -d '='
}

key() {
    if ! token --list-objects --type pubkey | grep -q "label:[[:space:]]*$1[[:space:]]*$"; then
        token --keypairgen --key-type "$2" --label "$1" --usage-sign >/dev/null
    fi
}

spki() {
    token --read-object --type pubkey --label "$1" --output-file "/tmp/$1.der" >/dev/null
    size="$(wc -c < "/tmp/$1.der")"
    if [ "$size" -ne "$2" ]; then
        echo "work-access-keys: $1 public key is $size bytes of DER, not $2" >&2
        exit 1
    fi
}

key work-access-client EC:prime256v1
key work-access-dpop EC:prime256v1
key work-access-service EC:edwards25519

spki work-access-client 91
x="$(tail -c 64 /tmp/work-access-client.der | head -c 32 | b64url)"
y="$(tail -c 32 /tmp/work-access-client.der | b64url)"
printf '{"kty":"EC","crv":"P-256","use":"sig","x":"%s","y":"%s"}\n' "$x" "$y" > "$WORK_ACCESS_KEYS/work-client.jwk"

spki work-access-service 44
x="$(tail -c 32 /tmp/work-access-service.der | b64url)"
printf '{"kty":"OKP","crv":"Ed25519","use":"sig","x":"%s"}\n' "$x" > "$WORK_ACCESS_KEYS/work-service.jwk"

echo "work-access-keys: work-client.jwk and work-service.jwk written"
