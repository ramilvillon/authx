CREATE TABLE `app_services` (
	`id` varchar(36) NOT NULL,
	`org_id` varchar(36) NOT NULL,
	`client_id` varchar(64) NOT NULL,
	`client_secret_hash` varchar(255),
	`name` varchar(255) NOT NULL,
	`slug` varchar(64) NOT NULL,
	`audience` varchar(128) NOT NULL,
	`type` varchar(16) NOT NULL,
	`redirect_uris` text NOT NULL DEFAULT ('[]'),
	`created_at` datetime NOT NULL,
	CONSTRAINT `app_services_id` PRIMARY KEY(`id`),
	CONSTRAINT `app_services_client_id_unique` UNIQUE(`client_id`),
	CONSTRAINT `app_services_audience_unique` UNIQUE(`audience`)
);
--> statement-breakpoint
CREATE TABLE `memberships` (
	`id` varchar(36) NOT NULL,
	`user_id` varchar(36) NOT NULL,
	`org_id` varchar(36) NOT NULL,
	`created_at` datetime NOT NULL,
	CONSTRAINT `memberships_id` PRIMARY KEY(`id`),
	CONSTRAINT `memberships_user_id_org_id_unique` UNIQUE(`user_id`,`org_id`)
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` varchar(36) NOT NULL,
	`slug` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`created_at` datetime NOT NULL,
	CONSTRAINT `organizations_id` PRIMARY KEY(`id`),
	CONSTRAINT `organizations_slug_unique` UNIQUE(`slug`)
);
--> statement-breakpoint
ALTER TABLE `permissions` DROP INDEX `permissions_key_unique`;--> statement-breakpoint
ALTER TABLE `roles` DROP INDEX `roles_name_unique`;--> statement-breakpoint
ALTER TABLE `permissions` ADD `app_service_id` varchar(36) NOT NULL;--> statement-breakpoint
ALTER TABLE `refresh_tokens` ADD `app_service_id` varchar(36) NOT NULL;--> statement-breakpoint
ALTER TABLE `roles` ADD `app_service_id` varchar(36) NOT NULL;--> statement-breakpoint
ALTER TABLE `permissions` ADD CONSTRAINT `permissions_app_service_id_key_unique` UNIQUE(`app_service_id`,`key`);--> statement-breakpoint
ALTER TABLE `roles` ADD CONSTRAINT `roles_app_service_id_name_unique` UNIQUE(`app_service_id`,`name`);--> statement-breakpoint
CREATE INDEX `app_services_org_idx` ON `app_services` (`org_id`);