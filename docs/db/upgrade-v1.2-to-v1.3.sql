-- SSO-server: schema upgrade v1.2 -> v1.3 for DBAs (MySQL 8.0.13+ / 8.4 dialect).
--
-- Generated with `python manage.py sqlmigrate <app> <migration>` against MySQL 8.4.11 (branch feat/sso-v1.3);
-- identical on 8.0.46. The PREFERRED way is scripts/upgrade_db.sh (Django migrate: it records each step in
-- django_migrations and runs the post-migrate permission sync). Use this file only when DDL must go through a
-- DBA. It touches ONLY SSO-owned tables (sso_*, plus FKs to auth_user / auth_permission); nothing in myFinance's
-- tables changes. Run it as the DDL account (sso_migrator: CREATE, ALTER, INDEX, REFERENCES; no DROP needed).
--
-- Order matters (foreign keys): sso 0002 -> sso 0003 -> application 0002 -> sso 0004 -> sso 0005 -> sso 0006.
-- Check first which are already applied and run only the missing blocks:
--   SELECT app, name FROM django_migrations WHERE app IN ('sso','application') ORDER BY app, id;
-- A v1.2b database already has sso 0002_v12a_service_registry_sessions: skip block 1.
-- MySQL DDL is not transactional: if a block fails half-way, fix the cause and run the remaining statements of
-- that block, or roll back with the notes at the end.
--
-- After the DDL: (1) the INSERT INTO django_migrations at the end of each block tells Django the step is done;
-- (2) run once, as sso_migrator, `python manage.py migrate` (it then has nothing to apply but runs post-migrate:
-- content types + auth_permission rows for the new models and the code-defined application.sso_admin);
-- (3) `python manage.py sso_schema_check` must print "schema OK".
--
-- New tables / columns per version (also README §5 and docs/SSO-Setup.md "Upgrading the database"):
--   v1.2a  sso_serviceclient.app_codename, .notify_url; table sso_revokedsession
--   v1.3a  sso_serviceclient.secret_rotated_at; tables sso_serviceclient_permissions, sso_adminauditlog,
--          sso_adminreauth, sso_application; sso_application_permission_record.app_codename, .deprecated_at,
--          .description; table sso_usertombstone
--   v1.3b  sso_serviceclient.kind, .owner_id (FK auth_user), .device_name, .public_key, .public_key_fingerprint
--          (unique), .last_used, .can_delegate, .can_register_devices
--   v1.3c  sso_serviceclient.notify_events (json, default []), .notify_secret_enc; tables sso_webhookevent,
--          sso_webhookdelivery

-- Select the SSO database first (or run: mysql dcWebUsers < this-file.sql). Change the name if yours differs.
USE dcWebUsers;

-- GUARD: this file UPGRADES an existing v1.2 SSO schema. If the next statement fails with
-- "Table 'dcWebUsers.sso_serviceclient' doesn't exist", this is a FIRST INSTALL (no sso_* tables yet):
-- stop here and run scripts/upgrade_db.sh instead (Django migrate creates all SSO tables from scratch).
SELECT COUNT(*) AS sso_serviceclient_rows FROM `sso_serviceclient`;

-- ============================================================================ block 1: sso.0002_v12a_service_registry_sessions (v1.2a)
--
-- Add field app_codename to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `app_codename` varchar(63) NULL;
--
-- Add field notify_url to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `notify_url` varchar(500) NULL;
--
-- Create model RevokedSession
--
CREATE TABLE `sso_revokedsession` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `sid` varchar(64) NOT NULL UNIQUE, `revoked_at` datetime(6) NOT NULL, `reason` varchar(32) NOT NULL, `user_id` integer NOT NULL);
ALTER TABLE `sso_revokedsession` ADD CONSTRAINT `sso_revokedsession_user_id_edf23801_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('sso', '0002_v12a_service_registry_sessions', UTC_TIMESTAMP(6));

-- ============================================================================ block 2: sso.0003_v13a (v1.3a)
--
-- Add field permissions to serviceclient
--
CREATE TABLE `sso_serviceclient_permissions` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `serviceclient_id` bigint NOT NULL, `permission_id` integer NOT NULL);
--
-- Add field secret_rotated_at to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `secret_rotated_at` datetime(6) NULL;
--
-- Create model AdminAuditLog
--
CREATE TABLE `sso_adminauditlog` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `ts` datetime(6) NOT NULL, `actor_type` varchar(16) NOT NULL, `actor_id` varchar(128) NOT NULL, `actor_ip` varchar(64) NOT NULL, `action` varchar(64) NOT NULL, `target_type` varchar(32) NOT NULL, `target_id` varchar(191) NOT NULL, `before` json NULL, `after` json NULL, `request_id` varchar(64) NOT NULL, `result` varchar(16) NOT NULL, `stepup` bool NOT NULL);
--
-- Create model AdminReauth
--
CREATE TABLE `sso_adminreauth` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `token_hash` varchar(64) NOT NULL UNIQUE, `sid` varchar(64) NOT NULL, `ip` varchar(64) NOT NULL, `created` datetime(6) NOT NULL, `expires_at` datetime(6) NOT NULL, `user_id` integer NOT NULL);
ALTER TABLE `sso_serviceclient_permissions` ADD CONSTRAINT `sso_serviceclient_permis_serviceclient_id_permiss_bfb9691b_uniq` UNIQUE (`serviceclient_id`, `permission_id`);
ALTER TABLE `sso_serviceclient_permissions` ADD CONSTRAINT `sso_serviceclient_pe_serviceclient_id_2b0207e7_fk_sso_servi` FOREIGN KEY (`serviceclient_id`) REFERENCES `sso_serviceclient` (`id`);
ALTER TABLE `sso_serviceclient_permissions` ADD CONSTRAINT `sso_serviceclient_pe_permission_id_ee70a95a_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`);
CREATE INDEX `sso_adminauditlog_ts_d2853cdb` ON `sso_adminauditlog` (`ts`);
CREATE INDEX `sso_adminauditlog_actor_id_2bbbf484` ON `sso_adminauditlog` (`actor_id`);
CREATE INDEX `sso_adminauditlog_action_d84b1928` ON `sso_adminauditlog` (`action`);
CREATE INDEX `sso_audit_target_idx` ON `sso_adminauditlog` (`target_type`, `target_id`);
ALTER TABLE `sso_adminreauth` ADD CONSTRAINT `sso_adminreauth_user_id_90c1cc5e_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('sso', '0003_v13a', UTC_TIMESTAMP(6));

-- ============================================================================ block 3: application.0002_v13a (v1.3a)
--
-- Create model Application
--
CREATE TABLE `sso_application` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `app_codename` varchar(63) NOT NULL UNIQUE, `name` varchar(200) NOT NULL, `description` varchar(1000) NOT NULL, `version` integer UNSIGNED NOT NULL CHECK (`version` >= 0), `created` datetime(6) NOT NULL, `updated` datetime(6) NOT NULL);
--
-- Change Meta options on applicationaccess
--
-- (no-op)
--
-- Add field app_codename to applicationpermissionrecord
--
ALTER TABLE `sso_application_permission_record` ADD COLUMN `app_codename` varchar(63) NULL;
--
-- Add field deprecated_at to applicationpermissionrecord
--
ALTER TABLE `sso_application_permission_record` ADD COLUMN `deprecated_at` datetime(6) NULL;
--
-- Add field description to applicationpermissionrecord
--
ALTER TABLE `sso_application_permission_record` ADD COLUMN `description` varchar(1000) DEFAULT '' NOT NULL;
ALTER TABLE `sso_application_permission_record` ALTER COLUMN `description` DROP DEFAULT;
CREATE INDEX `sso_application_permission_record_app_codename_54a2669b` ON `sso_application_permission_record` (`app_codename`);
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('application', '0002_v13a', UTC_TIMESTAMP(6));

-- ============================================================================ block 4: sso.0004_v13a_tombstone (v1.3a)
--
-- Create model UserTombstone
--
CREATE TABLE `sso_usertombstone` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `user_id` bigint NOT NULL, `username` varchar(150) NOT NULL, `deleted_at` datetime(6) NOT NULL);
CREATE INDEX `sso_usertombstone_user_id_b4a3b0d5` ON `sso_usertombstone` (`user_id`);
CREATE INDEX `sso_usertombstone_deleted_at_34c81a07` ON `sso_usertombstone` (`deleted_at`);
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('sso', '0004_v13a_tombstone', UTC_TIMESTAMP(6));

-- ============================================================================ block 5: sso.0005_v13b (v1.3b)
--
-- Add field can_delegate to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `can_delegate` bool DEFAULT b'0' NOT NULL;
ALTER TABLE `sso_serviceclient` ALTER COLUMN `can_delegate` DROP DEFAULT;
--
-- Add field can_register_devices to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `can_register_devices` bool DEFAULT b'0' NOT NULL;
ALTER TABLE `sso_serviceclient` ALTER COLUMN `can_register_devices` DROP DEFAULT;
--
-- Add field device_name to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `device_name` varchar(200) DEFAULT '' NOT NULL;
ALTER TABLE `sso_serviceclient` ALTER COLUMN `device_name` DROP DEFAULT;
--
-- Add field kind to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `kind` varchar(16) DEFAULT 'service' NOT NULL;
ALTER TABLE `sso_serviceclient` ALTER COLUMN `kind` DROP DEFAULT;
--
-- Add field last_used to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `last_used` datetime(6) NULL;
--
-- Add field owner to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `owner_id` integer NULL , ADD CONSTRAINT `sso_serviceclient_owner_id_dee829e4_fk_auth_user_id` FOREIGN KEY (`owner_id`) REFERENCES `auth_user`(`id`);
--
-- Add field public_key to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `public_key` longtext NULL;
--
-- Add field public_key_fingerprint to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `public_key_fingerprint` varchar(64) NULL UNIQUE;
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('sso', '0005_v13b', UTC_TIMESTAMP(6));

-- ============================================================================ block 6: sso.0006_v13c (v1.3c)
--
-- Create model WebhookEvent
--
CREATE TABLE `sso_webhookevent` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `type` varchar(40) NOT NULL, `created` datetime(6) NOT NULL, `data` json NOT NULL);
--
-- Add field notify_events to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `notify_events` json DEFAULT ('[]') NOT NULL;
--
-- Add field notify_secret_enc to serviceclient
--
ALTER TABLE `sso_serviceclient` ADD COLUMN `notify_secret_enc` longtext NULL;
--
-- Create model WebhookDelivery
--
CREATE TABLE `sso_webhookdelivery` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, `status` varchar(16) NOT NULL, `attempts` integer UNSIGNED NOT NULL CHECK (`attempts` >= 0), `next_attempt_at` datetime(6) NOT NULL, `window_start` datetime(6) NOT NULL, `claimed_at` datetime(6) NULL, `last_status` integer NULL, `last_error` varchar(200) NOT NULL, `delivered_at` datetime(6) NULL, `client_id` bigint NOT NULL, `event_id` bigint NOT NULL);
CREATE INDEX `sso_webhookevent_type_1dbb428e` ON `sso_webhookevent` (`type`);
CREATE INDEX `sso_webhookevent_created_8afb7a2c` ON `sso_webhookevent` (`created`);
ALTER TABLE `sso_webhookdelivery` ADD CONSTRAINT `sso_webhookdelivery_client_id_14b43789_fk_sso_serviceclient_id` FOREIGN KEY (`client_id`) REFERENCES `sso_serviceclient` (`id`);
ALTER TABLE `sso_webhookdelivery` ADD CONSTRAINT `sso_webhookdelivery_event_id_7860fad8_fk_sso_webhookevent_id` FOREIGN KEY (`event_id`) REFERENCES `sso_webhookevent` (`id`);
CREATE INDEX `sso_webhookdelivery_status_d415da8f` ON `sso_webhookdelivery` (`status`);
CREATE INDEX `sso_webhookdelivery_next_attempt_at_a12a77ba` ON `sso_webhookdelivery` (`next_attempt_at`);
CREATE INDEX `sso_whd_due_idx` ON `sso_webhookdelivery` (`status`, `next_attempt_at`);
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('sso', '0006_v13c', UTC_TIMESTAMP(6));

-- ============================================================================ verification
SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()
  AND table_name IN ('sso_revokedsession','sso_serviceclient_permissions','sso_adminauditlog','sso_adminreauth',
                     'sso_application','sso_usertombstone','sso_webhookevent','sso_webhookdelivery');   -- 8 rows
SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sso_serviceclient'
  AND column_name IN ('app_codename','notify_url','secret_rotated_at','kind','owner_id','device_name','public_key',
                      'public_key_fingerprint','last_used','can_delegate','can_register_devices','notify_events',
                      'notify_secret_enc');                                                           -- 13

-- ============================================================================ rollback notes (read, do not run blindly)
-- Restore preferred: scripts/upgrade_db.sh wrote backups/sso-tables-<db>-<ts>.sql.gz (SSO tables + the SSO rows of
-- django_migrations) before migrating. Rollback = stop web + webhooks, deploy the previous image (v1.2b), then:
--   a) Django way, with the v1.3 image (it has the backward steps). Grant DROP BEFORE starting: without it MySQL
--      refuses the DROP TABLE after the column drops already ran (DDL is not transactional) and leaves a half state
--      (then finish with b):
--        GRANT DROP ON dcWebUsers.* TO 'sso_migrator'@'172.31.250.%';
--        python manage.py migrate application 0001 && python manage.py migrate sso 0002
--        REVOKE DROP ON dcWebUsers.* FROM 'sso_migrator'@'172.31.250.%';
--      This drops the v1.3 tables/columns: audit log, devices, webhook history are LOST. Tested on 8.4: afterwards
--      the v1.2b image sees no pending migrations and no model drift, and data of the v1.2 tables is unchanged.
--   b) SQL way (DBA, same effect), newest first:
--        DROP TABLE sso_webhookdelivery, sso_webhookevent, sso_usertombstone, sso_adminreauth, sso_adminauditlog,
--                   sso_serviceclient_permissions, sso_application;
--        ALTER TABLE sso_serviceclient DROP FOREIGN KEY sso_serviceclient_owner_id_dee829e4_fk_auth_user_id;
--        DELETE FROM sso_serviceclient WHERE kind = 'device';        -- device rows did not exist in v1.2
--        ALTER TABLE sso_serviceclient DROP COLUMN notify_events, DROP COLUMN notify_secret_enc, DROP COLUMN kind,
--          DROP COLUMN owner_id, DROP COLUMN device_name, DROP COLUMN public_key, DROP COLUMN public_key_fingerprint,
--          DROP COLUMN last_used, DROP COLUMN can_delegate, DROP COLUMN can_register_devices,
--          DROP COLUMN secret_rotated_at;
--        DROP INDEX sso_application_permission_record_app_codename_54a2669b ON sso_application_permission_record;
--        ALTER TABLE sso_application_permission_record DROP COLUMN app_codename, DROP COLUMN deprecated_at,
--          DROP COLUMN description;
--        DELETE FROM django_migrations WHERE (app = 'sso' AND name IN ('0003_v13a','0004_v13a_tombstone','0005_v13b',
--          '0006_v13c')) OR (app = 'application' AND name = '0002_v13a');
--   c) Full restore of the SSO tables from the backup: DROP the sso_* / token_blacklist_* tables, load the dump
--      (zcat ... | mysql dcWebUsers), and replace the SSO rows of django_migrations:
--        DELETE FROM django_migrations WHERE app IN ('sso','application','token_blacklist');  then the dump's INSERTs.
--      Tokens issued after the backup become unknown to the blacklist (users log in again).
-- Rows that v1.3's post-migrate added to auth_permission / django_content_type / sso_application_permission_record
-- (e.g. application.sso_admin) can stay: v1.2 ignores them. Never touch auth_user or other myFinance tables.
-- Running the v1.2b image on the v1.3 schema (no schema rollback) works for login, refresh, logout and introspect
-- (v1.3 only ADDs). It can NOT create service clients (the new NOT NULL columns have no DB default), so do that
-- only after a real rollback (a/b/c).
