# Widen MySQL location ids past the 16-bit counter (ANT-2026-C82AB02V).
# Fresh installs already get INT UNSIGNED from mysql.schema.
# Existing databases stay SMALLINT until this is applied. Widen
# alert.location_id first, then location.id. Safe to re-run.
#
# alert_ipv6 exists only after convert-db-ipv6.sql. Widen it when
# that table is present. A MODIFY on a missing table would stop
# this script.
#
# ALTER TABLE ... MODIFY rebuilds the table and locks writes.
# On a large alert table this takes a while.
#
# Usage:
#   mysql -u ossec -p ossec < upgrade-location-id-mysql.sql

ALTER TABLE alert MODIFY location_id INT UNSIGNED NOT NULL;

SET @have_alert_ipv6 := (
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = 'alert_ipv6'
);
SET @sql := IF(@have_alert_ipv6 = 0,
    'SELECT ''alert_ipv6 not present'' AS info',
    'ALTER TABLE alert_ipv6 MODIFY location_id INT UNSIGNED NOT NULL');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

ALTER TABLE location MODIFY id INT UNSIGNED NOT NULL AUTO_INCREMENT;
