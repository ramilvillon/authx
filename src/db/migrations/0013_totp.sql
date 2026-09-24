CREATE TABLE `totp_recovery_codes` (
	`id` varchar(36) NOT NULL,
	`user_id` varchar(36) NOT NULL,
	`code_hash` varchar(64) NOT NULL,
	`used_at` datetime,
	CONSTRAINT `totp_recovery_codes_id` PRIMARY KEY(`id`),
	CONSTRAINT `totp_recovery_codes_user_id_code_hash_unique` UNIQUE(`user_id`,`code_hash`)
);
--> statement-breakpoint
CREATE TABLE `user_totp` (
	`user_id` varchar(36) NOT NULL,
	`secret` varchar(255) NOT NULL,
	`enabled_at` datetime,
	`last_step` int NOT NULL DEFAULT 0,
	CONSTRAINT `user_totp_user_id` PRIMARY KEY(`user_id`)
);
