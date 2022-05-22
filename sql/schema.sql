CREATE DATABASE commandcenter;

CREATE USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'App1234!';
GRANT ALL ON commandcenter.* TO 'app'@'%';
FLUSH PRIVILEGES;

USE commandcenter;

CREATE table path_mapping (
  `id` int auto_increment primary key,
  `path` varchar(100) not null,
  `method` enum('GET', 'POST') not null,
  `token_type` enum('basic', 'bearer', 'custom', 'open') not null,
  `token_value` varchar(255) not null,
  `ssh_authorize_type` enum('password', 'private_key') not null,
  `ssh_authorize_value` varchar(255) not null,
  `ssh_host` varchar(100) not null,
  `ssh_user` varchar(100) not null,
  `ssh_port` varchar(10) not null,
  `ssh_command` text not null,
  `created_at` timestamp default current_timestamp,
  `updated_at` timestamp default null on update current_timestamp
);