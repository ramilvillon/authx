CREATE TABLE `client_roles` (
	`client_app_service_id` varchar(36) NOT NULL,
	`role_id` varchar(36) NOT NULL,
	CONSTRAINT `client_roles_client_app_service_id_role_id_pk` PRIMARY KEY(`client_app_service_id`,`role_id`)
);
