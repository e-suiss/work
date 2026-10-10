#!/bin/sh
set -eu

: "${SOFTHSM_TOKEN_LABEL:?}" "${SOFTHSM_SO_PIN:?}" "${SOFTHSM_USER_PIN:?}"

if ! softhsm2-util --show-slots | grep -q "Label:[[:space:]]*${SOFTHSM_TOKEN_LABEL}[[:space:]]*$"; then
    softhsm2-util --init-token --free \
        --label "${SOFTHSM_TOKEN_LABEL}" \
        --so-pin "${SOFTHSM_SO_PIN}" \
        --pin "${SOFTHSM_USER_PIN}"
fi

exec sleep infinity
