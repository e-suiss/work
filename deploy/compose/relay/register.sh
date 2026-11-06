#!/bin/sh
# T-99, MD-3, E-93
set -eu

: "${LOCAL_ACCESS_CLIENT_FILE:?}" "${LOCAL_BOOTSTRAP:?}" "${RELAY_REGION:?}"
RELAY_ACCESS_CLIENT_ID="$(cat "$LOCAL_ACCESS_CLIENT_FILE")"
export RELAY_ACCESS_CLIENT_ID
exec /app/bin/relay eval 'Code.eval_file("/usr/local/lib/relay-work/register.exs")'
