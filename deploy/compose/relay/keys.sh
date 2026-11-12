#!/bin/sh
# T-56, T-41, T-99
set -eu

: "${PKCS11_MODULE:?}" "${PKCS11_TOKEN:?}" "${PKCS11_PIN_FILE:?}" "${SOFTHSM_SO_PIN:?}"
: "${KEY_STORE_KEK_LABEL:?}" "${KEY_STORE_FINGERPRINT_LABEL:?}" "${KEY_STORE_CURSOR_LABEL:?}"
: "${LOCAL_ACCESS_KEYS:?}"

pin="$(tr -d '\n' < "$PKCS11_PIN_FILE")"
if ! softhsm2-util --show-slots | grep -q "Label:[[:space:]]*${PKCS11_TOKEN}[[:space:]]*$"; then
    softhsm2-util --init-token --free --label "$PKCS11_TOKEN" --so-pin "$SOFTHSM_SO_PIN" --pin "$pin" >/dev/null
fi

token() {
    pkcs11-tool --module "$PKCS11_MODULE" --token-label "$PKCS11_TOKEN" --login --pin "$pin" "$@"
}

has() {
    token --list-objects --type "$1" 2>/dev/null | grep -q "label:[[:space:]]*$2[[:space:]]*$"
}

pair() {
    has pubkey "$1" || token --keypairgen --key-type "$2" --label "$1" --usage-sign >/dev/null
}

secret() {
    label="$1"
    shift
    has secrkey "$label" || token --keygen --label "$label" --sensitive "$@" >/dev/null
}

b64url() {
    base64 -w 0 | tr '+/' '-_' | tr -d '='
}

spki() {
    token --read-object --type pubkey --label "$1" --output-file "/tmp/$1.out" >/dev/null
    if [ "$(head -c 10 "/tmp/$1.out")" = "-----BEGIN" ]; then
        grep -v -e '-----' "/tmp/$1.out" | base64 -d > "/tmp/$1.der"
    else
        cp "/tmp/$1.out" "/tmp/$1.der"
    fi
    size="$(wc -c < "/tmp/$1.der")"
    if [ "$size" -ne "$2" ]; then
        echo "relay-keys: $1 public key is $size bytes of DER, not $2" >&2
        exit 1
    fi
}

pair audit-checkpoint EC:edwards25519
pair subscriber-token EC:prime256v1
secret "$KEY_STORE_KEK_LABEL" --key-type AES:32
secret "$KEY_STORE_FINGERPRINT_LABEL" --key-type GENERIC:32 --usage-sign
secret "$KEY_STORE_CURSOR_LABEL" --key-type GENERIC:32 --usage-sign

# T-99, E-2
pair access-client EC:prime256v1
pair relay-access-service EC:edwards25519

spki access-client 91
x="$(tail -c 64 /tmp/access-client.der | head -c 32 | b64url)"
y="$(tail -c 32 /tmp/access-client.der | b64url)"
printf '{"kty":"EC","crv":"P-256","use":"sig","x":"%s","y":"%s"}\n' "$x" "$y" > "$LOCAL_ACCESS_KEYS/relay-client.jwk"

spki relay-access-service 44
x="$(tail -c 32 /tmp/relay-access-service.der | b64url)"
printf '{"kty":"OKP","crv":"Ed25519","use":"sig","x":"%s"}\n' "$x" > "$LOCAL_ACCESS_KEYS/relay-service.jwk"

echo "relay-keys: Relay's keys are in token $PKCS11_TOKEN; relay-client.jwk and relay-service.jwk written"
