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
    token --read-object --type pubkey --label "$1" --output-file "/tmp/$1.out" >/dev/null
    if [ "$(head -c 10 "/tmp/$1.out")" = "-----BEGIN" ]; then
        grep -v -e '-----' "/tmp/$1.out" | base64 -d > "/tmp/$1.der"
    else
        cp "/tmp/$1.out" "/tmp/$1.der"
    fi
    size="$(wc -c < "/tmp/$1.der")"
    if [ "$size" -ne "$2" ]; then
        echo "work-access-keys: $1 public key is $size bytes of DER, not $2" >&2
        exit 1
    fi
}

key work-access-client EC:prime256v1
key work-access-dpop EC:prime256v1
key work-access-service EC:edwards25519
key work-access-pep EC:prime256v1

spki work-access-client 91
x="$(tail -c 64 /tmp/work-access-client.der | head -c 32 | b64url)"
y="$(tail -c 32 /tmp/work-access-client.der | b64url)"
printf '{"kty":"EC","crv":"P-256","use":"sig","x":"%s","y":"%s"}\n' "$x" "$y" > "$WORK_ACCESS_KEYS/work-client.jwk"

spki work-access-service 44
x="$(tail -c 32 /tmp/work-access-service.der | b64url)"
printf '{"kty":"OKP","crv":"Ed25519","use":"sig","x":"%s"}\n' "$x" > "$WORK_ACCESS_KEYS/work-service.jwk"

echo "work-access-keys: work-client.jwk and work-service.jwk written"

# T-101
spki work-access-pep 91
csr="$WORK_ACCESS_KEYS/work-pep.csr"
if [ -f "$csr" ] \
    && openssl req -in "$csr" -noout -verify 2>/dev/null \
    && openssl req -in "$csr" -noout -pubkey | openssl pkey -pubin -outform DER | cmp -s - /tmp/work-access-pep.der; then
    echo "work-access-keys: work-pep.csr kept"
    exit 0
fi
PKCS11_PROVIDER_MODULE="$module" openssl req -new -provider pkcs11 -provider default \
    -key "pkcs11:token=$SOFTHSM_TOKEN_LABEL;object=work-access-pep;type=private?pin-value=$SOFTHSM_USER_PIN" \
    -subj /CN=work-pep -sha256 -out /tmp/work-pep.csr
openssl req -in /tmp/work-pep.csr -noout -verify
openssl req -in /tmp/work-pep.csr -noout -pubkey | openssl pkey -pubin -outform DER | cmp - /tmp/work-access-pep.der
cp /tmp/work-pep.csr "$csr.new"
mv "$csr.new" "$csr"
echo "work-access-keys: work-pep.csr written"
