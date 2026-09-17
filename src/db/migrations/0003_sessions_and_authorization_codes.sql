CREATE TABLE `authorization_codes` (
	`id` varchar(36) NOT NULL,
	`code_hash` varchar(64) NOT NULL,
	`user_id` varchar(36) NOT NULL,
	`app_service_id` varchar(36) NOT NULL,
	`redirect_uri` varchar(2048) NOT NULL,
	`code_challenge` varchar(128) NOT NULL,
	`code_challenge_method` varchar(8) NOT NULL,
	`scope` text NOT NULL,
	`expires_at` datetime NOT NULL,
	`consumed_at` datetime,
	`created_at` datetime NOT NULL,
	CONSTRAINT `authorization_codes_id` PRIMARY KEY(`id`),
	CONSTRAINT `authorization_codes_code_hash_unique` UNIQUE(`code_hash`)
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` varchar(36) NOT NULL,
	`user_id` varchar(36) NOT NULL,
	`token_hash` varchar(64) NOT NULL,
	`expires_at` datetime NOT NULL,
	`revoked_at` datetime,
	`created_at` datetime NOT NULL,
	CONSTRAINT `sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `sessions_token_hash_unique` UNIQUE(`token_hash`)
);
