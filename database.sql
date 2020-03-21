DROP database IF EXISTS `vt_scanned_ips_db`;
CREATE database vt_scanned_ips_db;
use vt_scanned_ips_db;
DROP TABLE `vt_scanned_ips_table`;
CREATE TABLE IF NOT EXISTS `vt_scanned_ips_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanned_ip` varchar(30) NOT NULL,
  `last_scanned_time` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;
DROP TABLE IF EXISTS `vt_scanned_resolutions_table`;
CREATE TABLE IF NOT EXISTS `vt_scanned_resolutions_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_id` int(11) NOT NULL,
  `domain` text NOT NULL,
  `scanned_time` text NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (ip_id) REFERENCES vt_scanned_ips_table(id)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;
DROP TABLE IF EXISTS `vt_scanned_urls_table`;
CREATE TABLE IF NOT EXISTS `vt_scanned_urls_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_id` int(11) NOT NULL,
  `url` text NOT NULL,
  `detections` text NULL,
  `scanned_time` text NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (ip_id) REFERENCES vt_scanned_ips_table(id)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;
DROP TABLE IF EXISTS `vt_scanned_downloads_table`;
CREATE TABLE IF NOT EXISTS `vt_scanned_downloads_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_id` int(11) NOT NULL,
  `hash` text NOT NULL,
  `detections` text NULL,
  `scanned_time` text NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (ip_id) REFERENCES vt_scanned_ips_table(id)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;
DROP TABLE IF EXISTS `vt_scanned_communicating_files_table`;
CREATE TABLE IF NOT EXISTS `vt_scanned_communicating_files_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_id` int(11) NOT NULL,
  `hash` text NOT NULL,
  `detections` text NULL,
  `scanned_time` text NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (ip_id) REFERENCES vt_scanned_ips_table(id)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;
DROP TABLE IF EXISTS `vt_scanned_referring_files_table`;
CREATE TABLE IF NOT EXISTS `vt_scanned_referring_files_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_id` int(11) NOT NULL,
  `hash` text NOT NULL,
  `detections` text NULL,
  `scanned_time` text NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (ip_id) REFERENCES vt_scanned_ips_table(id)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;
CREATE USER 'theemperor_read'@'localhost' IDENTIFIED WITH mysql_native_password BY '---REDACTED---';
GRANT SELECT ON vt_scanned_ips_db.* TO 'theemperor_read'@'localhost';
CREATE USER 'theemperor_write'@'localhost' IDENTIFIED WITH mysql_native_password BY '---REDACTED---';
GRANT INSERT,SELECT ON vt_scanned_ips_db.* TO 'theemperor_write'@'localhost';
CREATE USER 'theemperor_update'@'localhost' IDENTIFIED WITH mysql_native_password BY '---REDACTED---';
GRANT SELECT,UPDATE ON vt_scanned_ips_db.vt_scanned_ips_table TO 'theemperor_update'@'localhost';
# if mysql version >= 8
#ALTER USER 'theemperor_read'@'localhost' IDENTIFIED BY '---REDACTED---';
#ALTER USER 'theemperor_write'@'localhost' IDENTIFIED BY '---REDACTED---';
#ALTER USER 'theemperor_update'@'localhost' IDENTIFIED BY '---REDACTED---';
