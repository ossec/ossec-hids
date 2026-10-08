-- Upgrade an existing PostgreSQL agent table for issue #1363 / PR #2340.
-- Fresh installs already get this from postgresql.schema.
--
-- - Widen name to VARCHAR(128) (matches OS_IsValidName).
-- - Remove duplicate (server_id, name) rows, keeping the newest
--   last_contact (lowest id on a tie).
-- - Add UNIQUE (server_id, name) so a failed SELECT cannot insert a second row.
--
-- Usage:
--   psql -U ossec -d ossec -f upgrade-agent-1363-postgresql.sql

ALTER TABLE agent ALTER COLUMN name TYPE VARCHAR(128);

DELETE FROM agent a
USING agent b
WHERE a.server_id = b.server_id
  AND a.name = b.name
  AND (a.last_contact < b.last_contact
       OR (a.last_contact = b.last_contact AND a.id > b.id));

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agent_server_name'
    ) THEN
        ALTER TABLE agent ADD CONSTRAINT agent_server_name UNIQUE (server_id, name);
    END IF;
END $$;
