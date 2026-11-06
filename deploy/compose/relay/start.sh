#!/bin/sh
# T-51, T-99, T-41
set -eu

: "${LOCAL_ACCESS_CLIENT_FILE:?}" "${LOCAL_TLS_CERT:?}" "${LOCAL_TLS_KEY:?}" "${PORT:?}"
RELAY_ACCESS_CLIENT_ID="$(cat "$LOCAL_ACCESS_CLIENT_FILE")"
export RELAY_ACCESS_CLIENT_ID
socat "OPENSSL-LISTEN:443,reuseaddr,fork,cert=${LOCAL_TLS_CERT},key=${LOCAL_TLS_KEY},verify=0" "TCP:127.0.0.1:${PORT}" &
exec /app/bin/relay "$@"
