CREATE TABLE `passkeys` (
	`id` varchar(36) NOT NULL,
	`user_id` varchar(36) NOT NULL,
	`credential_id` text NOT NULL,
	`credential_id_hash` varchar(64) NOT NULL,
	`public_key` text NOT NULL,
	`counter` bigint unsigned NOT NULL DEFAULT 0,
	`transports` varchar(255) NOT NULL DEFAULT '',
	`aaguid` varchar(36) NOT NULL,
	`backed_up` boolean NOT NULL,
	`created_at` datetime NOT NULL,
	`last_used_at` datetime,
	CONSTRAINT `passkeys_id` PRIMARY KEY(`id`),
	CONSTRAINT `passkeys_credential_id_hash_unique` UNIQUE(`credential_id_hash`)
);
--> statement-breakpoint
CREATE TABLE `webauthn_challenges` (
	`id` varchar(36) NOT NULL,
	`challenge_hash` varchar(64) NOT NULL,
	`purpose` varchar(16) NOT NULL,
	`user_id` varchar(36),
	`expires_at` datetime NOT NULL,
	`consumed_at` datetime,
	CONSTRAINT `webauthn_challenges_id` PRIMARY KEY(`id`),
	CONSTRAINT `webauthn_challenges_challenge_hash_unique` UNIQUE(`challenge_hash`)
);
--> statement-breakpoint
CREATE INDEX `passkeys_user_idx` ON `passkeys` (`user_id`);