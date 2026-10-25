-- ==============================================================================
-- Gasha Enterprise Cyber Operations Platform — MySQL / cPanel Schema
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS `safeguard_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `safeguard_db`;

-- Users Table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(60) NOT NULL UNIQUE,
    `email` VARCHAR(120) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(40) DEFAULT 'SecOps Analyst',
    `avatar_url` VARCHAR(255) DEFAULT '',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `last_login` TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Scans & Heuristic Results History
CREATE TABLE IF NOT EXISTS `scans` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NULL,
    `scan_type` VARCHAR(40) NOT NULL,
    `target_input` TEXT NOT NULL,
    `threat_score` INT NOT NULL,
    `verdict` VARCHAR(80) NOT NULL,
    `verdict_tier` VARCHAR(30) NOT NULL,
    `summary` TEXT NOT NULL,
    `details_json` LONGTEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_scan_type` (`scan_type`),
    INDEX `idx_threat_score` (`threat_score`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Active Incident Stream
CREATE TABLE IF NOT EXISTS `incidents` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `title` VARCHAR(255) NOT NULL,
    `category` VARCHAR(100) NOT NULL,
    `severity` VARCHAR(40) NOT NULL,
    `target_node` VARCHAR(120) NOT NULL,
    `status` VARCHAR(50) DEFAULT 'ACTIVE',
    `day_number` VARCHAR(10) NOT NULL,
    `month_label` VARCHAR(10) NOT NULL,
    `participants_count` INT DEFAULT 3,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Threat Intelligence Feed
CREATE TABLE IF NOT EXISTS `threat_intel_feed` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `title` VARCHAR(255) NOT NULL,
    `severity_badge` VARCHAR(60) NOT NULL,
    `preview_tag` VARCHAR(60) NOT NULL,
    `description` TEXT NOT NULL,
    `footer_note` TEXT NOT NULL,
    `image_url` VARCHAR(255) NOT NULL,
    `author_name` VARCHAR(80) NOT NULL,
    `author_avatar` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
