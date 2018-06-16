-- phpMyAdmin SQL Dump
-- version 4.4.14
-- http://www.phpmyadmin.net
--
-- Host: 127.0.0.1
-- Generation Time: Nov 12, 2016 at 02:53 AM
-- Server version: 5.6.26
-- PHP Version: 5.6.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `bitcoin`
--

-- --------------------------------------------------------

--
-- Table structure for table `bitcoin_user`
--

CREATE TABLE IF NOT EXISTS `bitcoin_user` (
  `id` int(10) unsigned NOT NULL,
  `mailaddr` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

--
-- Dumping data for table `bitcoin_user`
--

INSERT INTO `bitcoin_user` (`id`, `mailaddr`, `password`) VALUES
(1, 'test@test.com', 'sha1$dc3d4449$1$72a816ecd86ca5e38c0ca8243adecf5eddb17344'),
(18, 'jhs@test.com', 'sha1$c985b7ed$1$1202d5c48820e3d3823cf3f7a17137f9cf056754'),
(20, 'sss@test.com', 'sha1$96f1c016$1$e10964f52e7c49f6380ef9d774b5e11af5d12fea'),
(21, 'aaa@test.com', 'sha1$9985e661$1$9c5b43d142bf5455ce34fc2c29e2a7a73acab072');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `bitcoin_user`
--
ALTER TABLE `bitcoin_user`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `bitcoin_user`
--
ALTER TABLE `bitcoin_user`
  MODIFY `id` int(10) unsigned NOT NULL AUTO_INCREMENT,AUTO_INCREMENT=22;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
