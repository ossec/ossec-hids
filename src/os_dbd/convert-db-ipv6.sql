# SQL script for converting existing agent and alert tables to the new 
# schema for handling longer IPv6 addresses.  This creates two tables 
# agent_ipv6 and alert_ipv6 which will replace agent and alert.

use ossec;

CREATE TABLE IF NOT EXISTS  agent_ipv6
    (
    id              SMALLINT    UNSIGNED NOT NULL   AUTO_INCREMENT,
    server_id       SMALLINT    UNSIGNED NOT NULL,
    last_contact    INT         UNSIGNED NOT NULL,
    ip_address      VARCHAR(46)          NOT NULL,
    version         VARCHAR(32)          NOT NULL,
    name            VARCHAR(64)          NOT NULL,
    information     VARCHAR(128)         NOT NULL,
    PRIMARY KEY  (id, server_id)
    );

CREATE TABLE IF NOT EXISTS  alert_ipv6
    (
    id              INT         UNSIGNED NOT NULL  AUTO_INCREMENT,
    server_id       SMALLINT    UNSIGNED NOT NULL,
    rule_id         MEDIUMINT   UNSIGNED NOT NULL,
    level           TINYINT     UNSIGNED,
    timestamp       INT         UNSIGNED NOT NULL,
    location_id     SMALLINT    UNSIGNED NOT NULL,
    src_ip          VARCHAR(46),
    dst_ip          VARCHAR(46),
    src_port        SMALLINT    UNSIGNED,
    dst_port        SMALLINT    UNSIGNED,
    alertid         VARCHAR(30) DEFAULT NULL,
    user            TEXT        NOT NULL,
    full_log        TEXT        NOT NULL,
    is_hidden       TINYINT NOT NULL DEFAULT '0',
    tld             VARCHAR(5)  NOT NULL DEFAULT '',
    PRIMARY KEY (id, server_id),
    INDEX       (alertid),
    INDEX       (level),
    INDEX       time (timestamp),
    INDEX       (rule_id),
    INDEX       (src_ip),
    INDEX       (tld)
    );

insert agent_ipv6
       select id, server_id, last_contact, inet_ntoa(ip_address), 
              version, name, information
       from agent;

insert alert_ipv6
       select id, server_id, rule_id, level, timestamp, location_id, 
              inet_ntoa(src_ip), inet_ntoa(dst_ip), src_port, dst_port, 
              alertid, user, full_log, is_hidden, tld
       from alert;

# Move the converted tables into place:
# 
#   rename table agent to agent_old;
#   rename table agent_ipv6 to agent;
#
#   rename table alert to alert_old;
#   rename table alert_ipv6 to alert;

# If everything looks ok, the old tables can deleted using:
#
#   drop table agent_old;
#   drop table alert_old;
