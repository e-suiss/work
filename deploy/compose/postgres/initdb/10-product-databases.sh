#!/usr/bin/env bash
# T-51, T-8, T-36, OP-2, OP-12
set -euo pipefail

create_product() {
    local product="$1" owner_password="$2" app_password="$3"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
        -v db="$product" \
        -v owner="${product}_owner" \
        -v app="${product}_app" \
        -v owner_password="$owner_password" \
        -v app_password="$app_password" <<'SQL'
CREATE ROLE :"owner" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'owner_password';
CREATE ROLE :"app" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
CREATE DATABASE :"db" OWNER :"owner";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"app";
SQL

    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$product" \
        -v owner="${product}_owner" \
        -v app="${product}_app" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" GRANT USAGE ON SCHEMAS TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" GRANT SELECT, INSERT, UPDATE ON TABLES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" GRANT USAGE, SELECT ON SEQUENCES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" GRANT EXECUTE ON FUNCTIONS TO :"app";
SQL
}

create_work() {
    local bootstrap=/work-bootstrap
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -f "$bootstrap/roles.sql"
    for role in work_owner work_app work_sequencer work_checkpointer work_publisher work_erasure \
        work_archive work_deriver work_reconciler; do
        psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
            -v role="$role" -v password="$WORK_DB_PASSWORD" <<'SQL'
ALTER ROLE :"role" LOGIN PASSWORD :'password';
SQL
    done
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -f "$bootstrap/databases.sql"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname work -f "$bootstrap/canonical.sql"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname work_derived -f "$bootstrap/derived.sql"
}

create_work
create_product access "$ACCESS_OWNER_PASSWORD" "$ACCESS_APP_PASSWORD"
create_product relay "$RELAY_OWNER_PASSWORD" "$RELAY_APP_PASSWORD"
