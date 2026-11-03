#!/bin/sh
# OP-33, OP-46, T-41
set -eu

: "${WITNESS_NAME:?}"
db=/var/lib/litewitness/witness.db
agent=/run/litewitness/agent.sock
key=/run/litewitness/witness.key
vkey=/run/litewitness-public/witness.vkey

rm -f "$key" "$key.pub"
ssh-keygen -q -t ed25519 -N '' -C "$WITNESS_NAME" -f "$key"
ssh-agent -a "$agent" >/dev/null
SSH_AUTH_SOCK="$agent" ssh-add -q "$key"
rm -f "$key"
fingerprint="$(ssh-keygen -l -E sha256 -f "$key.pub" | cut -d ' ' -f 2)"

public="$(cut -d ' ' -f 2 "$key.pub" | base64 -d | tail -c 32 | base64 -w 0)"
id="$({ printf '%s\n\004' "$WITNESS_NAME"; printf '%s' "$public" | base64 -d; } | sha256sum | cut -c 1-8)"
encoded="$({ printf '\004'; printf '%s' "$public" | base64 -d; } | base64 -w 0)"
printf '%s+%s+%s\n' "$WITNESS_NAME" "$id" "$encoded" >"$vkey.new"
mv -f "$vkey.new" "$vkey"
echo "witness vkey $WITNESS_NAME+$id+$encoded"

IFS=';'
for entry in ${WITNESS_LOGS:-}; do
    [ -n "$entry" ] || continue
    origin="${entry%% *}"
    log_vkey="${entry#* }"
    witnessctl add-log -db "$db" -origin "$origin"
    witnessctl add-key -db "$db" -origin "$origin" -key "$log_vkey"
done
unset IFS

exec litewitness -db "$db" -name "$WITNESS_NAME" -key "$fingerprint" -ssh-agent "$agent" -listen 0.0.0.0:7380
