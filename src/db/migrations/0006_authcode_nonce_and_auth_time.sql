ALTER TABLE `authorization_codes` ADD `nonce` varchar(255);--> statement-breakpoint
ALTER TABLE `authorization_codes` ADD `auth_time` datetime NOT NULL;