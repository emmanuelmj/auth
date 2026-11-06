--
-- Converts pending_email_registrations.expires_at from TIMESTAMP to TIMESTAMPTZ.
-- Existing TIMESTAMP values have no timezone metadata. Set auth.legacy_tz to the
-- timezone used by the application when those values were written:
--
--   PGOPTIONS="-c auth.legacy_tz=Asia/Kolkata" psql "$DATABASE_URL" -f migrations/002_pending_email_expiry_timestamptz.sql
--
-- If that timezone cannot be established and rows remain, do not guess: stop
-- and determine whether to invalidate those pending registrations first. An
-- empty table can be converted without a timezone because it has no values.
-- This migration is safe to re-run; missing tables and already-converted
-- columns are skipped. Stop application writers before running this migration.
-- The explicit ACCESS EXCLUSIVE lock prevents concurrent writes after it is
-- acquired; stopping writers also prevents older application instances from
-- writing incompatible timestamps after the migration commits.

BEGIN;

SET LOCAL lock_timeout = '10s';

DO $$
DECLARE
    legacy_tz text;
    column_type text;
BEGIN
    SELECT c.data_type::text
      INTO column_type
      FROM information_schema.columns c
     WHERE c.table_schema = current_schema()
       AND c.table_name = 'pending_email_registrations'
       AND c.column_name = 'expires_at';

    IF column_type = 'timestamp without time zone' THEN
        -- The column lookup above confirms both the table and target column exist.
        LOCK TABLE pending_email_registrations IN ACCESS EXCLUSIVE MODE;

        -- Recheck after locking so concurrent migration invocations remain safe.
        SELECT c.data_type::text
          INTO column_type
          FROM information_schema.columns c
         WHERE c.table_schema = current_schema()
           AND c.table_name = 'pending_email_registrations'
           AND c.column_name = 'expires_at';

        IF column_type = 'timestamp without time zone' THEN
            legacy_tz := NULLIF(current_setting('auth.legacy_tz', true), '');
            IF legacy_tz IS NULL THEN
                IF EXISTS (SELECT 1 FROM pending_email_registrations) THEN
                    RAISE EXCEPTION 'pending registration expiries have no timezone metadata; set auth.legacy_tz after establishing the original application timezone, or invalidate pending registrations first';
                END IF;
                legacy_tz := 'UTC';
            END IF;

            -- Validate the supplied zone before changing the schema.
            PERFORM now() AT TIME ZONE legacy_tz;

            EXECUTE format(
                'ALTER TABLE pending_email_registrations ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE %L',
                legacy_tz
            );
            RAISE NOTICE 'pending_email_registrations.expires_at converted using %', legacy_tz;
        ELSIF column_type IS NOT NULL AND column_type <> 'timestamp with time zone' THEN
            RAISE EXCEPTION 'unexpected type for pending_email_registrations.expires_at: %', column_type;
        END IF;
    ELSIF column_type IS NOT NULL AND column_type <> 'timestamp with time zone' THEN
        RAISE EXCEPTION 'unexpected type for pending_email_registrations.expires_at: %', column_type;
    END IF;
END
$$;

COMMIT;
