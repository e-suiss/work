#!/bin/sh
# T-51, T-99, T-41, E-91
set -eu

: "${LOCAL_ACCESS_CLIENT_FILE:?}" "${LOCAL_TLS_CERT:?}" "${LOCAL_TLS_KEY:?}" "${PORT:?}"
RELAY_ACCESS_CLIENT_ID="$(cat "$LOCAL_ACCESS_CLIENT_FILE")"
export RELAY_ACCESS_CLIENT_ID
umask 077
cat "$LOCAL_TLS_CERT" "$LOCAL_TLS_KEY" > /tmp/relay-proxy.pem
haproxy -db -f /etc/relay-proxy.cfg &
exec /app/bin/relay "$@"
