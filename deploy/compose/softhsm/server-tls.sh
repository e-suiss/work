#!/bin/sh
# T-56, T-102
set -eu

: "${SOFTHSM_TOKEN_LABEL:?}" "${SOFTHSM_USER_PIN:?}" "${WORK_SERVER_KEY:?}"

module=/usr/lib/softhsm/libsofthsm2.so
label=work-server-tls
id=777374
token() {
    pkcs11-tool --module "$module" --token-label "$SOFTHSM_TOKEN_LABEL" --login --pin "$SOFTHSM_USER_PIN" "$@"
}
held() {
    token --list-objects --type "$1" | grep -q "label:[[:space:]]*$label[[:space:]]*$"
}

umask 077
openssl pkey -in "$WORK_SERVER_KEY" -pubout -outform DER -out /tmp/server.pub.der
if held pubkey && held privkey; then
    token --read-object --type pubkey --label "$label" --output-file /tmp/held.out >/dev/null
    if [ "$(head -c 10 /tmp/held.out)" = "-----BEGIN" ]; then
        openssl pkey -pubin -in /tmp/held.out -outform DER -out /tmp/held.der
    else
        cp /tmp/held.out /tmp/held.der
    fi
    if cmp -s /tmp/held.der /tmp/server.pub.der; then
        echo "work-server-tls: key kept"
        exit 0
    fi
fi
for type in privkey pubkey; do
    while held "$type"; do
        token --delete-object --type "$type" --label "$label" >/dev/null
    done
done
openssl pkey -in "$WORK_SERVER_KEY" -outform DER -out /tmp/server.key.der
token --write-object /tmp/server.key.der --type privkey --label "$label" --id "$id" --usage-sign --sensitive >/dev/null
rm -f /tmp/server.key.der
token --write-object /tmp/server.pub.der --type pubkey --label "$label" --id "$id" --usage-sign >/dev/null
echo "work-server-tls: key written"
