#!/bin/bash
# Local/QA only (deployment plan §2.1 / R29). Runs once, on the first start of an empty data volume.
# Creates the same two accounts as production (§6.2) with caching_sha2_password (default plugin on MySQL 8.0 and 8.4; set explicitly so both behave alike).
# Syntax valid on 8.0.4+ and 8.4 (CREATE USER IF NOT EXISTS ... IDENTIFIED WITH caching_sha2_password BY).
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
