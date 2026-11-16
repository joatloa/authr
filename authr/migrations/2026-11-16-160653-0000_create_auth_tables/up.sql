CREATE TABLE `user` (
    `id` VARCHAR(36) PRIMARY KEY NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `emailVerified` BOOLEAN NOT NULL DEFAULT FALSE,
    `image` TEXT,
    `createdAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
);

CREATE TABLE `session` (
    `id` VARCHAR(36) PRIMARY KEY NOT NULL,
    `userId` VARCHAR(36) NOT NULL,
    `token` VARCHAR(255) NOT NULL UNIQUE,
    `expiresAt` TIMESTAMP(3) NOT NULL,
    `ipAddress` TEXT,
    `userAgent` TEXT,
    `createdAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    CONSTRAINT `fk_session_userId` FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE
);

CREATE TABLE `account` (
    `id` VARCHAR(36) PRIMARY KEY NOT NULL,
    `userId` VARCHAR(36) NOT NULL,
    `accountId` VARCHAR(255) NOT NULL,
    `providerId` VARCHAR(255) NOT NULL,
    `accessToken` TEXT,
    `refreshToken` TEXT,
    `accessTokenExpiresAt` TIMESTAMP(3),
    `refreshTokenExpiresAt` TIMESTAMP(3),
    `scope` TEXT,
    `idToken` TEXT,
    `passwordHash` TEXT,
    `createdAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    CONSTRAINT `fk_account_userId` FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE
);

CREATE TABLE `verification` (
    `id` VARCHAR(36) PRIMARY KEY NOT NULL,
    `identifier` VARCHAR(255) NOT NULL,
    `value` TEXT NOT NULL,
    `expiresAt` TIMESTAMP(3) NOT NULL,
    `createdAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
);

-- Indexes for query performance
CREATE INDEX `idx_session_userId` ON `session`(`userId`);
CREATE INDEX `idx_account_userId` ON `account`(`userId`);
CREATE INDEX `idx_verification_identifier` ON `verification`(`identifier`);
