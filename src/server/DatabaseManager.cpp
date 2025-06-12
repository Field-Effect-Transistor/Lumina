//  DatabaseManager.cpp

#include "DatabaseManager.hpp"

DatabaseManager::DatabaseManager(const std::string& db_path) {
    std::cout << "[INFO] DB oppening" << std::endl;    

    std::filesystem::path db_path_fs(db_path);
    auto dir = db_path_fs.parent_path();
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }

    rc = sqlite3_open_v2(db_path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to open database: " << sqlite3_errmsg(db_) << std::endl;
        throw std::runtime_error("Failed to open database");
    }
    
    const char* create_db_sql = R"(
    -- CREATE DATABASE IF NOT EXISTS lumina_db;

CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    is_verified INTEGER NOT NULL DEFAULT 0,
    vpn_ip TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    status TEXT NOT NULL DEFAULT 'AWAITING_VERIFICATION' CHECK(status IN ('ACTIVE', 'AWAITING_VERIFICATION', 'SUSPENDED'))
);

-- Auth and restore password tokens (AuthTokens)
CREATE TABLE IF NOT EXISTS AuthTokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_value_hash TEXT UNIQUE NOT NULL,
    token_type TEXT NOT NULL CHECK(token_type IN ('EMAIL_CONFIRMATION', 'PASSWORD_RESET')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS RefreshTokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    device_info TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    password_hash TEXT DEFAULT 0,
    salt TEXT DEFAULT 0,
    owner_user_id INTEGER NOT NULL,
    max_members INTEGER NOT NULL DEFAULT 5,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_user_id) REFERENCES Users(id) ON DELETE RESTRICT
);

-- Таблиця Членів Групи (GroupMembers)
CREATE TABLE IF NOT EXISTS GroupMembers (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES Groups(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON Users (email);

-- Індекси для AuthTokens
CREATE UNIQUE INDEX IF NOT EXISTS idx_authtokens_token_value_hash ON AuthTokens (token_value_hash);
CREATE INDEX IF NOT EXISTS idx_authtokens_user_id_type ON AuthTokens (user_id, token_type);
CREATE INDEX IF NOT EXISTS idx_authtokens_expires_at ON AuthTokens (expires_at);

-- Індекси для RefreshTokens
CREATE UNIQUE INDEX IF NOT EXISTS idx_refreshtokens_token_hash ON RefreshTokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_refreshtokens_user_id ON RefreshTokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refreshtokens_expires_at ON RefreshTokens (expires_at);

-- Індекси для Groups
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name ON Groups (name);
CREATE INDEX IF NOT EXISTS idx_groups_owner_user_id ON Groups (owner_user_id);

-- Індекси для GroupMembers
CREATE INDEX IF NOT EXISTS idx_groupmembers_group_id ON GroupMembers (group_id);

-- Приклад тригера для автоматичного оновлення updated_at в таблиці Users (SQLite)
CREATE TRIGGER IF NOT EXISTS update_users_updated_at
AFTER UPDATE ON Users
FOR EACH ROW
BEGIN
    UPDATE Users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;

-- Приклад тригера для автоматичного оновлення updated_at в таблиці Groups (SQLite)
CREATE TRIGGER IF NOT EXISTS update_groups_updated_at
AFTER UPDATE ON Groups
FOR EACH ROW
BEGIN
    UPDATE Groups SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;
    )";
    

    rc = sqlite3_exec(db_, create_db_sql, nullptr, nullptr, &zErrMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to execute SQL: " << zErrMsg << std::endl;
        sqlite3_free(zErrMsg);
        throw std::runtime_error("Failed to execute SQL");
    }



}

DatabaseManager::~DatabaseManager() {
    std::cout << "[INFO] DB closing" << std::endl;
    rc = sqlite3_close(db_);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to close database: " << sqlite3_errmsg(db_) << std::endl;
    }
    db_ = nullptr;
}
