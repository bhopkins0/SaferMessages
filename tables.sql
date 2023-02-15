CREATE TABLE `users` (
	`acc_id` INT NOT NULL AUTO_INCREMENT,
	`username` VARCHAR(64) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`password` VARCHAR(75) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	PRIMARY KEY (acc_id)
);

CREATE TABLE `messages` (
	`message_id` INT NOT NULL AUTO_INCREMENT,
	`user_from` VARCHAR(64) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`user_to` VARCHAR(64) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`message_password` VARCHAR(75) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`message_iv` VARCHAR(16) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`message_tag` VARCHAR(24) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`message` VARCHAR(1000) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	PRIMARY KEY (message_id)
);
