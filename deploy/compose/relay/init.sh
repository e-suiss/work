#!/bin/sh
# T-51, T-36, OP-28, T-41, T-99
set -eu

: "${LOCAL_BOOTSTRAP:?}" "${LOCAL_TRUST:?}" "${LOCAL_ACCESS_CA:?}" "${LOCAL_ACCESS_CLIENT_FILE:?}"
: "${AUDIT_S3_ENDPOINT:?}" "${AUDIT_S3_BUCKET:?}" "${AUDIT_S3_REGION:?}" "${AUDIT_S3_ACCESS_KEY_ID:?}"
: "${AUDIT_S3_SECRET_ACCESS_KEY_FILE:?}" "${LOCAL_MIGRATOR_DATABASE_URL:?}"

cat /etc/relay-system-ca.crt "$LOCAL_ACCESS_CA" > "$LOCAL_TRUST/ca-certificates.crt.new"
mv "$LOCAL_TRUST/ca-certificates.crt.new" "$LOCAL_TRUST/ca-certificates.crt"

jq -er '.clients[] | select(.product == "relay") | .client_id' "$LOCAL_BOOTSTRAP" > "$LOCAL_ACCESS_CLIENT_FILE.new"
mv "$LOCAL_ACCESS_CLIENT_FILE.new" "$LOCAL_ACCESS_CLIENT_FILE"
RELAY_ACCESS_CLIENT_ID="$(cat "$LOCAL_ACCESS_CLIENT_FILE")"
export RELAY_ACCESS_CLIENT_ID
echo "relay-init: Relay's Access client is $RELAY_ACCESS_CLIENT_ID"

/app/bin/relay eval 'Relay.Release.bootstrap()'
DATABASE_URL="$LOCAL_MIGRATOR_DATABASE_URL" /app/bin/relay eval 'Relay.Release.migrate()'
/app/bin/relay eval 'Relay.Release.bootstrap()'

s3() {
    curl -sS -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:${AUDIT_S3_REGION}:s3" \
        --user "${AUDIT_S3_ACCESS_KEY_ID}:$(tr -d '\n' < "$AUDIT_S3_SECRET_ACCESS_KEY_FILE")" "$@"
}

bucket="$AUDIT_S3_ENDPOINT/$AUDIT_S3_BUCKET"
case "$(s3 -X PUT -H 'x-amz-bucket-object-lock-enabled: true' "$bucket")" in
    200 | 409) ;;
    *)
        echo "relay-init: the audit bucket $AUDIT_S3_BUCKET could not be created" >&2
        exit 1
        ;;
esac
lock='<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>'
md5="$(printf %s "$lock" | openssl dgst -md5 -binary | base64)"
status="$(s3 -X PUT -H "content-md5: $md5" --data-binary "$lock" "$bucket?object-lock")"
echo "relay-init: audit bucket $AUDIT_S3_BUCKET ready (object lock configuration: $status)"
