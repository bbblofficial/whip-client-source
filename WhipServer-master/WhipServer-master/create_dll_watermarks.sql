-- Migration: create dll_watermarks table
-- Run once on the VPS PostgreSQL database

CREATE TABLE IF NOT EXISTS dll_watermarks (
    id          UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    session_uuid VARCHAR(36)  NOT NULL,
    user_id     UUID,
    discord_id  VARCHAR(255),
    hwid        VARCHAR(128),
    ip          VARCHAR(45),
    pc_name     VARCHAR(128),
    hmac_hex    VARCHAR(32),
    download_id UUID,
    created_at  TIMESTAMP    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_watermark_session_uuid ON dll_watermarks(session_uuid);
CREATE        INDEX IF NOT EXISTS idx_watermark_user         ON dll_watermarks(user_id);
CREATE        INDEX IF NOT EXISTS idx_watermark_created      ON dll_watermarks(created_at);
