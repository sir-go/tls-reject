CREATE TABLE `events` (
    `event` varchar(255) NOT NULL,
    `time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`event`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `https_domains` (
    `hostname` varchar(255) NOT NULL,
    KEY `hostname` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
