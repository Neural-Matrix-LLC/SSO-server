-- SSO-server: schema upgrade v1.3 (v1.3a-c) -> v1.3d for DBAs (MySQL 8.0.13+ / 8.4 dialect).
--
-- Generated with `python manage.py sqlmigrate sso 0007` against MySQL 8.4 and 8.0 (branch feat/v1.3d-admin-ui;
-- identical on both). The PREFERRED way is scripts/upgrade_db.sh (Django migrate: it records the step in
-- django_migrations). Use this file only when DDL must go through a DBA. It touches ONLY the SSO-owned table
-- sso_adminauditlog; nothing in myFinance's tables changes. Run it as the DDL account (sso_migrator: ALTER, INDEX;
-- no DROP needed).
--
-- Prerequisite: the v1.3 schema (sso 0003-0006, application 0002), see docs/db/upgrade-v1.2-to-v1.3.sql. Check:
--   SELECT app, name FROM django_migrations WHERE app = 'sso' ORDER BY id;   -- last row must be 0006_v13c
-- If 0007_v13d_audit_channel is already listed, there is nothing to do.
--
-- After the DDL: (1) the INSERT INTO django_migrations at the end tells Django the step is done; (2) run once, as
-- sso_migrator, `python manage.py migrate` (nothing to apply; runs post-migrate); (3) `python manage.py
-- sso_schema_check` must print "schema OK".
--
-- New in v1.3d: sso_adminauditlog.channel varchar(16) NOT NULL DEFAULT 'api' + index. Existing rows get 'api'
-- (before v1.3d only the admin REST API wrote audit rows). Django keeps no DB default after its own migrate; the
-- DEFAULT below is dropped again in the same block to match exactly what `migrate` leaves behind.
-- Locking: the ADD COLUMN is INSTANT on MySQL 8.0.29+ / 8.4; CREATE INDEX is an online in-place build (concurrent
-- reads and writes allowed, short metadata locks at start and end). Only sso_adminauditlog is touched.

-- Select the SSO database first (or run: mysql dcWebUsers < this-file.sql). Change the name if yours differs.
USE dcWebUsers;

-- GUARD: this file UPGRADES an existing v1.3 SSO schema. If the next statement fails with
-- "Table 'dcWebUsers.sso_adminauditlog' doesn't exist", the database is older than v1.3 (or a first install):
-- stop here and apply docs/db/upgrade-v1.2-to-v1.3.sql first, or run scripts/upgrade_db.sh instead.
SELECT COUNT(*) AS sso_adminauditlog_rows FROM `sso_adminauditlog`;

-- ============================================================================ block 1: sso.0007_v13d_audit_channel (v1.3d)
--
-- Add field channel to adminauditlog
--
ALTER TABLE `sso_adminauditlog` ADD COLUMN `channel` varchar(16) DEFAULT 'api' NOT NULL;
ALTER TABLE `sso_adminauditlog` ALTER COLUMN `channel` DROP DEFAULT;
CREATE INDEX `sso_adminauditlog_channel_42298c3f` ON `sso_adminauditlog` (`channel`);
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('sso', '0007_v13d_audit_channel', UTC_TIMESTAMP(6));

-- ============================================================================ verification
SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sso_adminauditlog'
  AND column_name = 'channel';                                                                 -- 1
SELECT channel, COUNT(*) FROM `sso_adminauditlog` GROUP BY channel;                            -- only 'api' rows

-- ============================================================================ rollback notes (read, do not run blindly)
-- The v1.3 image (before v1.3d) works on the v1.3d schema without a rollback: it does not know the column, and its
-- INSERTs would fail ONLY because channel has no DB default. So a real rollback is needed before running v1.3c code
-- that writes audit rows. Options, after stopping web + webhooks and deploying the previous image:
--   a) Django way, with the v1.3d image:   python manage.py migrate sso 0006_v13c
--      (an ALTER, no DROP grant needed; the index goes with the column). Audit rows keep everything except channel.
--   b) SQL way (DBA, same effect):
--        ALTER TABLE sso_adminauditlog DROP INDEX sso_adminauditlog_channel_42298c3f, DROP COLUMN channel;
--        DELETE FROM django_migrations WHERE app = 'sso' AND name = '0007_v13d_audit_channel';
--   c) Keep the column but give it a DB default so old code can insert:
--        ALTER TABLE sso_adminauditlog ALTER COLUMN channel SET DEFAULT 'api';
-- Never touch auth_user or other myFinance tables.
