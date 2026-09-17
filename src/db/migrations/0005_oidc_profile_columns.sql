ALTER TABLE `users` ADD `email_verified` boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `name` varchar(255);--> statement-breakpoint
ALTER TABLE `users` ADD `given_name` varchar(255);--> statement-breakpoint
ALTER TABLE `users` ADD `family_name` varchar(255);--> statement-breakpoint
ALTER TABLE `users` ADD `picture` varchar(1024);