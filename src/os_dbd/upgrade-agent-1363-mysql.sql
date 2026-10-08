# Upgrade an existing MySQL agent table for issue #1363 / PR #2340.
# Fresh installs already get this from mysql.schema.
#
# - Widen name to VARCHAR(128) (matches OS_IsValidName).
# - Remove duplicate (server_id, name) rows, keeping the newest
#   last_contact (lowest id on a tie).
# - Add UNIQUE (server_id, name) so a failed SELECT cannot insert a second row.
#
# Usage:
#   mysql -u ossec -p ossec < upgrade-agent-1363-mysql.sql

ALTER TABLE agent MODIFY name VARCHAR(128) NOT NULL;

DELETE a FROM agent a
INNER JOIN agent b
  ON a.server_id = b.server_id
 AND a.name = b.name
 AND (a.last_contact < b.last_contact
      OR (a.last_contact = b.last_contact AND a.id > b.id));

-- Safe to re-run after the unique key exists: skip if already present.
SET @have_uk := (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'agent'
      AND index_name = 'agent_server_name'
);
SET @sql := IF(@have_uk = 0,
    'ALTER TABLE agent ADD UNIQUE KEY agent_server_name (server_id, name)',
    'SELECT ''agent_server_name already present'' AS info');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
