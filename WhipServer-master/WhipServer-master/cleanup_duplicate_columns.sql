-- One-shot cleanup of columns Hibernate auto-created in dev because
-- @Entity fields lacked explicit @Column(name="…") and ddl-auto was
-- set to `update`. Prisma is the single source of truth — keep the
-- snake_case columns, drop the lowercase no-underscore duplicates.
--
-- Safe to re-run: every DROP is conditional on column existence.
--
-- After running this, set ddl-auto=validate so Hibernate can never
-- spawn a duplicate again (already done in application-dev.yml).

DO $$
BEGIN
    -- configs: createdat / updatedat / ispublic
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='configs' AND column_name='createdat') THEN
        ALTER TABLE configs DROP COLUMN createdat;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='configs' AND column_name='updatedat') THEN
        ALTER TABLE configs DROP COLUMN updatedat;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='configs' AND column_name='ispublic') THEN
        ALTER TABLE configs DROP COLUMN ispublic;
    END IF;

    -- user_configs: addedat / isowner
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='user_configs' AND column_name='addedat') THEN
        ALTER TABLE user_configs DROP COLUMN addedat;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name='user_configs' AND column_name='isowner') THEN
        ALTER TABLE user_configs DROP COLUMN isowner;
    END IF;
END $$;
