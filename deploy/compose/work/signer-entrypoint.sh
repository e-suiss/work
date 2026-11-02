#!/bin/sh
set -eu

: "${SOFTHSM_TOKEN_LABEL:?}" "${SOFTHSM_USER_PIN:?}" "${WORK_SIGNER_KEY_LABEL:?}" "${WORK_SIGNER_PIN_FILE:?}"

module=/usr/lib/softhsm/libsofthsm2.so
token() {
    pkcs11-tool --module "$module" --token-label "$SOFTHSM_TOKEN_LABEL" --login --pin "$SOFTHSM_USER_PIN" "$@"
}

if ! token --list-objects --type pubkey | grep -q "label:[[:space:]]*${WORK_SIGNER_KEY_LABEL}[[:space:]]*$"; then
    token --keypairgen --key-type EC:edwards25519 --label "$WORK_SIGNER_KEY_LABEL" --usage-sign >/dev/null
fi

umask 077
printf '%s\n' "$SOFTHSM_USER_PIN" > "$WORK_SIGNER_PIN_FILE"
exec /usr/local/bin/work-signer --config /etc/work-signer/signer.toml
