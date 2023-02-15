CREATE TABLE `users` (
	`acc_id` INT NOT NULL AUTO_INCREMENT,
	`username` VARCHAR(64) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	`password` VARCHAR(75) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
	PRIMARY KEY (acc_id)
);

