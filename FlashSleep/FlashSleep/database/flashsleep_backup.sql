-- MySQL dump 10.13  Distrib 8.0.33, for Win64 (x86_64)
--
-- Host: localhost    Database: flashsleep
-- ------------------------------------------------------
-- Server version       8.0.33

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
...

--
-- Database: `flashsleep`
--
CREATE DATABASE IF NOT EXISTS `flashsleep` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */;
USE `flashsleep`;

--
-- Table structure for table `users`
--
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `gender` varchar(10) NOT NULL,
  `birthdate` date NOT NULL,
  `email` varchar(100) NOT NULL UNIQUE,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);

--
-- Dumping data for table `users`
--
INSERT INTO `users` (`id`, `first_name`, `last_name`, `gender`, `birthdate`, `email`, `password`) VALUES
(1, 'John', 'Doe', 'Male', '2000-01-01', 'john@example.com', 'hashedpassword1'),
(2, 'Jane', 'Smith', 'Female', '1998-05-12', 'jane@example.com', 'hashedpassword2');

