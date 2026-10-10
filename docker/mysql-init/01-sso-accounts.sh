#!/bin/bash
# Local/QA only (deployment plan §2.1 / R29). Runs once, on the first start of an empty data volume.
# Creates the same two accounts as production (§6.2) with MySQL 8.4 default auth (caching_sha2_password).
# '%' host part is acceptable here only. No REQUIRE SSL locally (see README open questions).
set -euo pipefail
: "${SSO_TEST_APP_PASSWORD:?}" "${SSO_TEST_MIGRATOR_PASSWORD:?}" "${MYSQL_DATABASE:?}"
mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'sso_app'@'%' IDENTIFIED WITH caching_sha2_password BY '${SSO_TEST_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${MYSQL_DATABASE}\`.* TO 'sso_app'@'%';
CREATE USER IF NOT EXISTS 'sso_migrator'@'%' IDENTIFIED WITH caching_sha2_password BY '${SSO_TEST_MIGRATOR_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON \`${MYSQL_DATABASE}\`.* TO 'sso_migrator'@'%';
FLUSH PRIVILEGES;
SQL
echo "sso-init: created sso_app (DML) and sso_migrator (DDL) on ${MYSQL_DATABASE}"
