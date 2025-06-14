//  DatabaseManager.cpp

#include "DatabaseManager.hpp"

DatabaseManager::DatabaseManager(const std::string& db_path) {
    std::lock_guard<std::mutex> lock(db_mutex_);
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
    password_hash TEXT DEFAULT NULL, 
    salt TEXT DEFAULT NULL,
    owner_user_id INTEGER NOT NULL,
    max_members INTEGER NOT NULL DEFAULT 50,
    description TEXT,
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

void finalize_statement(sqlite3_stmt* stmt, const std::string& operation_name, sqlite3* db) {
    if (stmt) {
        int rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            std::cerr << "[ERROR] Failed to finalize statement for " << operation_name << ": " << sqlite3_errmsg(db) << std::endl;
        }
    }
}


std::optional<int> DatabaseManager::addUser(
    const std::string& email,
    const std::string& password_hash,
    const std::string& salt,
    const std::string& initial_status
) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "INSERT INTO Users (email, password_hash, salt, status) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    int new_user_id = -1;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (addUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addUser_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, initial_status.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (addUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addUser_step", db_);
        return std::nullopt;
    } else {
        new_user_id = static_cast<int>(sqlite3_last_insert_rowid(db_));
    }

    finalize_statement(stmt, "addUser", db_);
    return new_user_id;
}

bool DatabaseManager::emailExists(const std::string& email) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT 1 FROM Users WHERE email = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    bool exists = false;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (emailExists): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "emailExists_prepare", db_);
        return false; // Або кинути виняток
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        exists = true;
    } else if (rc != SQLITE_DONE) { // Якщо не ROW і не DONE, то помилка
        std::cerr << "[ERROR] Failed to execute statement (emailExists): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "emailExists", db_);
    return exists;
}

// Допоміжна функція для заповнення UserRecord зі stmt
DatabaseManager::UserRecord DatabaseManager::fillUserRecordFromStatement(sqlite3_stmt* stmt) {
    UserRecord user;
    user.id = sqlite3_column_int(stmt, 0);
    user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    user.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    user.salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    user.is_verified = sqlite3_column_int(stmt, 4) == 1;
    const char* vpn_ip_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    if (vpn_ip_c_str) user.vpn_ip = vpn_ip_c_str;
    user.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
    user.updated_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    const char* last_login_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    if (last_login_c_str) user.last_login = last_login_c_str;
    user.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    return user;
}

std::optional<DatabaseManager::UserRecord> DatabaseManager::getUserByEmail(const std::string& email) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT id, email, password_hash, salt, is_verified, vpn_ip, created_at, updated_at, last_login, status FROM Users WHERE email = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::optional<UserRecord> userRecord = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getUserByEmail): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getUserByEmail_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        userRecord = fillUserRecordFromStatement(stmt);
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getUserByEmail): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getUserByEmail", db_);
    return userRecord;
}

std::optional<DatabaseManager::UserRecord> DatabaseManager::getUserById(int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT id, email, password_hash, salt, is_verified, vpn_ip, created_at, updated_at, last_login, status FROM Users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::optional<UserRecord> userRecord = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getUserById): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getUserById_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        userRecord = fillUserRecordFromStatement(stmt);
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getUserById): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getUserById", db_);
    return userRecord;
}

bool DatabaseManager::updateUserPassword(int user_id, const std::string& new_password_hash, const std::string& new_salt) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // updated_at оновиться автоматично завдяки тригеру
    const char* sql = "UPDATE Users SET password_hash = ?, salt = ? WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (updateUserPassword): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateUserPassword_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, new_salt.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (updateUserPassword): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateUserPassword_step", db_);
        return false;
    }
    
    bool success = sqlite3_changes(db_) > 0; // Перевіряємо, чи були змінені рядки
    finalize_statement(stmt, "updateUserPassword", db_);
    return success;
}

bool DatabaseManager::setUserVerified(int user_id, bool is_verified) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // updated_at оновиться автоматично завдяки тригеру
    const char* sql = "UPDATE Users SET is_verified = ?, status = CASE WHEN ? = 1 THEN 'ACTIVE' ELSE status END WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (setUserVerified): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "setUserVerified_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, is_verified ? 1 : 0);
    sqlite3_bind_int(stmt, 2, is_verified ? 1 : 0); // Для CASE виразу
    sqlite3_bind_int(stmt, 3, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (setUserVerified): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "setUserVerified_step", db_);
        return false;
    }
    
    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "setUserVerified", db_);
    return success;
}

bool DatabaseManager::updateUserStatus(int user_id, const std::string& new_status) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // updated_at оновиться автоматично завдяки тригеру
    const char* sql = "UPDATE Users SET status = ? WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (updateUserStatus): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateUserStatus_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (updateUserStatus): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateUserStatus_step", db_);
        return false;
    }
    
    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "updateUserStatus", db_);
    return success;
}

bool DatabaseManager::updateUserLastLogin(int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // updated_at оновиться автоматично завдяки тригеру, але last_login - окреме поле
    const char* sql = "UPDATE Users SET last_login = CURRENT_TIMESTAMP WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (updateUserLastLogin): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateUserLastLogin_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (updateUserLastLogin): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateUserLastLogin_step", db_);
        return false;
    }
    
    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "updateUserLastLogin", db_);
    return success;
}

bool DatabaseManager::assignVpnIpToUser(int user_id, const std::string& vpn_ip) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // updated_at оновиться автоматично завдяки тригеру
    const char* sql = "UPDATE Users SET vpn_ip = ? WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (assignVpnIpToUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "assignVpnIpToUser_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, vpn_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (assignVpnIpToUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "assignVpnIpToUser_step", db_);
        return false;
    }
    
    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "assignVpnIpToUser", db_);
    return success;
}

std::optional<std::string> DatabaseManager::getVpnIpForUser(int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT vpn_ip FROM Users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::optional<std::string> vpn_ip_opt = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getVpnIpForUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getVpnIpForUser_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char* vpn_ip_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (vpn_ip_c_str) { // Перевірка на NULL з бази даних
            vpn_ip_opt = vpn_ip_c_str;
        }
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getVpnIpForUser): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getVpnIpForUser", db_);
    return vpn_ip_opt;
}

bool DatabaseManager::deleteUser(int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Завдяки ON DELETE CASCADE, пов'язані токени та членство в групах будуть видалені автоматично
    const char* sql = "DELETE FROM Users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (deleteUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "deleteUser_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (deleteUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "deleteUser_step", db_);
        return false;
    }
    
    bool success = sqlite3_changes(db_) > 0; // Перевіряємо, чи був видалений рядок
    finalize_statement(stmt, "deleteUser", db_);
    return success;
}

int extractIpSuffix(const std::string& full_ip, const std::string& network_prefix) {
    if (full_ip.rfind(network_prefix, 0) == 0) { // Перевіряє, чи починається рядок з префікса
        std::string suffix_str = full_ip.substr(network_prefix.length());
        try {
            return std::stoi(suffix_str);
        } catch (const std::invalid_argument& ia) {
            std::cerr << "[WARNING] Invalid IP suffix format: " << suffix_str << " for IP: " << full_ip << std::endl;
        } catch (const std::out_of_range& oor) {
            std::cerr << "[WARNING] IP suffix out of range: " << suffix_str << " for IP: " << full_ip << std::endl;
        }
    } else {
        // std::cerr << "[DEBUG] IP " << full_ip << " does not match prefix " << network_prefix << std::endl;
    }
    return -1; // Помилка або невідповідність префіксу
}


// Отримує суфікс останньої IP-адреси, призначеної останньому створеному користувачеві
std::optional<int> DatabaseManager::getLastAssignedIpSuffix(const std::string& network_prefix) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Знаходимо користувача, створеного останнім, у якого є vpn_ip
    const char* sql = "SELECT vpn_ip FROM Users WHERE vpn_ip IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    std::optional<int> last_suffix = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getLastAssignedIpSuffix): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getLastAssignedIpSuffix_prepare", db_);
        return std::nullopt;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char* vpn_ip_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (vpn_ip_c_str) {
            int suffix = extractIpSuffix(vpn_ip_c_str, network_prefix);
            if (suffix != -1) {
                last_suffix = suffix;
            }
        }
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getLastAssignedIpSuffix): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getLastAssignedIpSuffix", db_);
    return last_suffix;
}

// Отримує всі призначені IP-суфікси
std::vector<int> DatabaseManager::getAllAssignedIpSuffixes(const std::string& network_prefix) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT vpn_ip FROM Users WHERE vpn_ip IS NOT NULL;";
    sqlite3_stmt* stmt = nullptr;
    std::vector<int> assigned_suffixes;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getAllAssignedIpSuffixes): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getAllAssignedIpSuffixes_prepare", db_);
        return assigned_suffixes; // Повернути порожній вектор
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* vpn_ip_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (vpn_ip_c_str) {
            int suffix = extractIpSuffix(vpn_ip_c_str, network_prefix);
            if (suffix != -1) {
                assigned_suffixes.push_back(suffix);
            }
        }
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getAllAssignedIpSuffixes): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getAllAssignedIpSuffixes", db_);
    return assigned_suffixes;
}


std::optional<std::string> DatabaseManager::findFreeVpnIp(const std::string& network_prefix) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::cout << "[INFO] Searching for a free VPN IP with prefix: " << network_prefix << std::endl;

    std::optional<int> last_assigned_suffix_opt = getLastAssignedIpSuffix(network_prefix);
    int start_search_suffix = 10; // Починаємо пошук з .10 за замовчуванням

    if (last_assigned_suffix_opt) {
        start_search_suffix = *last_assigned_suffix_opt + 1;
        std::cout << "[INFO] Last assigned IP suffix was " << *last_assigned_suffix_opt
                  << ". Starting search from " << start_search_suffix << "." << std::endl;
    } else {
        std::cout << "[INFO] No previously assigned IPs found with this prefix. Starting search from "
                  << start_search_suffix << "." << std::endl;
    }

    std::vector<int> all_assigned_suffixes_vec = getAllAssignedIpSuffixes(network_prefix);
    // Для швидкого пошуку перетворимо вектор у set
    std::set<int> assigned_suffixes_set(all_assigned_suffixes_vec.begin(), all_assigned_suffixes_vec.end());

    // Алгоритм:
    // 1. Шукаємо від (last_assigned_suffix + 1) до 255.
    // 2. Якщо не знайдено, шукаємо від 10 до last_assigned_suffix.

    // Діапазон пошуку
    const int MIN_IP_SUFFIX = 10;
    const int MAX_IP_SUFFIX = 254; // Включно

    // Перший етап пошуку: від start_search_suffix до MAX_IP_SUFFIX
    for (int current_suffix = start_search_suffix; current_suffix <= MAX_IP_SUFFIX; ++current_suffix) {
        if (current_suffix < MIN_IP_SUFFIX) { // Якщо last_assigned було < 9, то start_search_suffix може бути < 10
            current_suffix = MIN_IP_SUFFIX;
            if (current_suffix > MAX_IP_SUFFIX) break; // Якщо MIN_IP_SUFFIX вже > MAX_IP_SUFFIX
        }
        // Перевіряємо, чи суфікс вільний
        if (assigned_suffixes_set.find(current_suffix) == assigned_suffixes_set.end()) {
            std::string free_ip = network_prefix + std::to_string(current_suffix);
            std::cout << "[INFO] Found free IP (Phase 1): " << free_ip << std::endl;
            return free_ip;
        }
    }
    std::cout << "[INFO] Phase 1 search (from " << start_search_suffix << " to " << MAX_IP_SUFFIX << ") did not find a free IP." << std::endl;

    // Другий етап пошуку: від MIN_IP_SUFFIX до start_search_suffix - 1 (або до last_assigned_suffix_opt, якщо воно було)
    // Цей етап потрібен, якщо в першому етапі ми "перестрибнули" через 255 або якщо last_assigned_suffix_opt був порожнім
    // і ми почали з 10, а вільні були перед 10 (хоча це суперечить умові "від 10").
    // Логічніше шукати від MIN_IP_SUFFIX до *last_assigned_suffix_opt, якщо воно існує і менше start_search_suffix (після першого циклу).
    
    int limit_for_second_phase = start_search_suffix -1; // До попереднього перед тим, звідки почали перший цикл
    if (last_assigned_suffix_opt && *last_assigned_suffix_opt < limit_for_second_phase) {
         // Якщо ми почали не з 10, а з IP останнього користувача, то другий цикл має йти до цього IP
         limit_for_second_phase = *last_assigned_suffix_opt;
    }


    if (limit_for_second_phase >= MIN_IP_SUFFIX) { // Тільки якщо є сенс шукати в цьому діапазоні
        std::cout << "[INFO] Starting Phase 2 search (from " << MIN_IP_SUFFIX << " to " << limit_for_second_phase << ")." << std::endl;
        for (int current_suffix = MIN_IP_SUFFIX; current_suffix <= limit_for_second_phase; ++current_suffix) {
            if (assigned_suffixes_set.find(current_suffix) == assigned_suffixes_set.end()) {
                std::string free_ip = network_prefix + std::to_string(current_suffix);
                std::cout << "[INFO] Found free IP (Phase 2): " << free_ip << std::endl;
                return free_ip;
            }
        }
        std::cout << "[INFO] Phase 2 search did not find a free IP." << std::endl;
    } else {
        std::cout << "[INFO] Skipping Phase 2 search as the range is invalid or already covered." << std::endl;
    }


    std::cout << "[WARNING] No free VPN IP found in the range "
              << MIN_IP_SUFFIX << "-" << MAX_IP_SUFFIX
              << " for prefix " << network_prefix << std::endl;
    return std::nullopt; // Не знайдено вільної IP-адреси
}

bool DatabaseManager::addAuthToken(
    int user_id,
    const std::string& token_value_hash,
    const std::string& token_type,
    int validity_seconds
) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Розраховуємо expires_at
    // Використовуємо SQLite функцію datetime('now', '+X seconds')
    std::string sql_insert =
        "INSERT INTO AuthTokens (user_id, token_value_hash, token_type, expires_at) "
        "VALUES (?, ?, ?, datetime('now', '+" + std::to_string(validity_seconds) + " seconds'));";

    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql_insert.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (addAuthToken): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addAuthToken_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, token_value_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, token_type.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (addAuthToken): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addAuthToken_step", db_);
        return false;
    }

    finalize_statement(stmt, "addAuthToken", db_);
    return true;
}

// Допоміжна функція для заповнення AuthTokenRecord
DatabaseManager::AuthTokenRecord DatabaseManager::fillAuthTokenRecordFromStatement(sqlite3_stmt* stmt) {
    DatabaseManager::AuthTokenRecord token;
    token.id = sqlite3_column_int(stmt, 0);
    token.user_id = sqlite3_column_int(stmt, 1);
    token.token_value_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    token.token_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    token.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    token.expires_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    token.is_used = (sqlite3_column_int(stmt, 6) == 1);
    return token;
}

std::optional<DatabaseManager::AuthTokenRecord> DatabaseManager::getValidAuthTokenByHash(
    const std::string& token_value_hash,
    const std::string& token_type
) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Перевіряємо, що токен не використаний і термін дії не закінчився
    const char* sql =
        "SELECT id, user_id, token_value_hash, token_type, created_at, expires_at, is_used "
        "FROM AuthTokens "
        "WHERE token_value_hash = ? AND token_type = ? AND is_used = 0 AND expires_at > datetime('now');";
    sqlite3_stmt* stmt = nullptr;
    std::optional<AuthTokenRecord> tokenRecord = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getValidAuthTokenByHash): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getValidAuthTokenByHash_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, token_value_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, token_type.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        tokenRecord = fillAuthTokenRecordFromStatement(stmt);
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getValidAuthTokenByHash): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getValidAuthTokenByHash", db_);
    return tokenRecord;
}

bool DatabaseManager::markAuthTokenAsUsed(const std::string& token_value_hash) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "UPDATE AuthTokens SET is_used = 1 WHERE token_value_hash = ? AND is_used = 0;"; // Додаткова умова is_used = 0 для ідемпотентності
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (markAuthTokenAsUsed): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "markAuthTokenAsUsed_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, token_value_hash.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (markAuthTokenAsUsed): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "markAuthTokenAsUsed_step", db_);
        return false;
    }

    bool success = sqlite3_changes(db_) > 0; // Перевіряємо, чи був оновлений хоча б один рядок
    finalize_statement(stmt, "markAuthTokenAsUsed", db_);
    return success;
}

bool DatabaseManager::invalidateUserAuthTokens(int user_id, const std::string& token_type) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Позначаємо всі активні токени певного типу для користувача як використані
    const char* sql = "UPDATE AuthTokens SET is_used = 1 WHERE user_id = ? AND token_type = ? AND is_used = 0 AND expires_at > datetime('now');";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (invalidateUserAuthTokens): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "invalidateUserAuthTokens_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, token_type.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (invalidateUserAuthTokens): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "invalidateUserAuthTokens_step", db_);
        // Навіть якщо помилка, ми не повертаємо false, оскільки деякі токени могли бути інвалідовані
        // або помилка може бути некритичною (наприклад, немає таких токенів).
        // Кількість змінених рядків тут менш інформативна.
    }
    // Ми не можемо тут гарантувати успіх на основі sqlite3_changes(),
    // бо може не бути активних токенів для інвалідації.
    // Повертаємо true, якщо запит виконався без помилок SQLite.
    bool success = (rc == SQLITE_DONE);
    finalize_statement(stmt, "invalidateUserAuthTokens", db_);
    return success;
}

int DatabaseManager::deleteExpiredAuthTokens() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "DELETE FROM AuthTokens WHERE expires_at <= datetime('now') OR is_used = 1;";
    sqlite3_stmt* stmt = nullptr; // Хоча для sqlite3_exec він не потрібен, але для консистенції
                                 // можна було б також використовувати prepare/step/finalize

    // Для простоти можна використати sqlite3_exec, якщо немає параметрів
    // Але для підрахунку змінених рядків краще prepare/step
    // Або ще простіше:
    int changes_before = sqlite3_total_changes(db_);
    rc = sqlite3_exec(db_, sql, nullptr, 0, &zErrMsg); // zErrMsg визначено в класі
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] SQL error (deleteExpiredAuthTokens): " << zErrMsg << std::endl;
        sqlite3_free(zErrMsg);
        zErrMsg = nullptr; // Скидаємо, щоб не використовувати звільнену пам'ять
        return -1; // Позначка помилки
    }
    int changes_after = sqlite3_total_changes(db_);
    return changes_after - changes_before; // Кількість видалених рядків
}

bool DatabaseManager::addRefreshToken(
    int user_id,
    const std::string& token_hash,
    const std::string& device_info,
    int validity_seconds
) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql_insert =
        "INSERT INTO RefreshTokens (user_id, token_hash, device_info, expires_at) "
        "VALUES (?, ?, ?, datetime('now', '+" + std::to_string(validity_seconds) + " seconds'));";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql_insert.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (addRefreshToken): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addRefreshToken_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, token_hash.c_str(), -1, SQLITE_STATIC);
    if (!device_info.empty()) {
        sqlite3_bind_text(stmt, 3, device_info.c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3); // Якщо device_info порожній, вставляємо NULL
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (addRefreshToken): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addRefreshToken_step", db_);
        return false;
    }

    finalize_statement(stmt, "addRefreshToken", db_);
    return true;
}

// Допоміжна функція для заповнення RefreshTokenRecord
DatabaseManager::RefreshTokenRecord DatabaseManager::fillRefreshTokenRecordFromStatement(sqlite3_stmt* stmt) {
    DatabaseManager::RefreshTokenRecord token;
    token.id = sqlite3_column_int(stmt, 0);
    token.user_id = sqlite3_column_int(stmt, 1);
    token.token_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    const char* device_info_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    if (device_info_c_str) token.device_info = device_info_c_str;
    token.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    token.expires_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    token.is_revoked = (sqlite3_column_int(stmt, 6) == 1);
    const char* last_used_at_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    if (last_used_at_c_str) token.last_used_at = last_used_at_c_str;
    return token;
}

std::optional<DatabaseManager::RefreshTokenRecord> DatabaseManager::getValidRefreshTokenByHash(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql =
        "SELECT id, user_id, token_hash, device_info, created_at, expires_at, is_revoked, last_used_at "
        "FROM RefreshTokens "
        "WHERE token_hash = ? AND is_revoked = 0 AND expires_at > datetime('now');";
    sqlite3_stmt* stmt = nullptr;
    std::optional<RefreshTokenRecord> tokenRecord = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getValidRefreshTokenByHash): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getValidRefreshTokenByHash_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        tokenRecord = fillRefreshTokenRecordFromStatement(stmt);
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getValidRefreshTokenByHash): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getValidRefreshTokenByHash", db_);
    return tokenRecord;
}

bool DatabaseManager::revokeRefreshToken(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "UPDATE RefreshTokens SET is_revoked = 1 WHERE token_hash = ? AND is_revoked = 0;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (revokeRefreshToken): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "revokeRefreshToken_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (revokeRefreshToken): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "revokeRefreshToken_step", db_);
        return false;
    }

    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "revokeRefreshToken", db_);
    return success;
}

bool DatabaseManager::revokeAllRefreshTokensForUser(int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "UPDATE RefreshTokens SET is_revoked = 1 WHERE user_id = ? AND is_revoked = 0 AND expires_at > datetime('now');";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (revokeAllRefreshTokensForUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "revokeAllRefreshTokensForUser_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (revokeAllRefreshTokensForUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "revokeAllRefreshTokensForUser_step", db_);
        // Повертаємо false, оскільки запит не завершився успішно, хоча деякі могли бути відкликані
        return false; 
    }
    // Тут sqlite3_changes() покаже, скільки токенів було фактично відкликано.
    // Можна повернути true, якщо команда виконана, навіть якщо 0 токенів змінено (бо їх могло не бути).
    finalize_statement(stmt, "revokeAllRefreshTokensForUser", db_);
    return true;
}

bool DatabaseManager::updateRefreshTokenLastUsed(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "UPDATE RefreshTokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (updateRefreshTokenLastUsed): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateRefreshTokenLastUsed_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (updateRefreshTokenLastUsed): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateRefreshTokenLastUsed_step", db_);
        return false;
    }

    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "updateRefreshTokenLastUsed", db_);
    return success;
}

int DatabaseManager::deleteExpiredOrRevokedRefreshTokens() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "DELETE FROM RefreshTokens WHERE expires_at <= datetime('now') OR is_revoked = 1;";
    // Для простоти, як і раніше, можна використати sqlite3_exec,
    // але для підрахунку видалених рядків краще так:
    sqlite3_stmt* stmt = nullptr;
    int deleted_rows = 0;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (deleteExpiredOrRevokedRefreshTokens): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "deleteExpiredOrRevokedRefreshTokens_prepare", db_);
        return -1; // Помилка
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (deleteExpiredOrRevokedRefreshTokens): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "deleteExpiredOrRevokedRefreshTokens_step", db_);
        return -1; // Помилка
    }

    deleted_rows = sqlite3_changes(db_);
    finalize_statement(stmt, "deleteExpiredOrRevokedRefreshTokens", db_);
    return deleted_rows;
}

DatabaseManager::GroupRecord DatabaseManager::fillGroupRecordFromStatement(sqlite3_stmt* stmt) {
    DatabaseManager::GroupRecord group;
    group.id = sqlite3_column_int(stmt, 0);
    group.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

    const char* pass_hash_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    if (pass_hash_c_str) group.password_hash = pass_hash_c_str;

    const char* salt_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    if (salt_c_str) group.salt = salt_c_str;

    group.owner_user_id = sqlite3_column_int(stmt, 4);
    group.max_members = sqlite3_column_int(stmt, 5);

    const char* desc_c_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
    if (desc_c_str) group.description = desc_c_str;

    group.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    group.updated_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    return group;
}


std::optional<int> DatabaseManager::createGroup(
    const std::string& group_name,
    int owner_user_id,
    const std::optional<std::string>& description, // Змінено на optional
    int max_members,
    const std::optional<std::string>& password_hash, // Додано
    const std::optional<std::string>& salt           // Додано
) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "INSERT INTO Groups (name, owner_user_id, description, max_members, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    int new_group_id = -1;

    // Спочатку додаємо власника як члена групи
    // Ця логіка має бути тут або в сервісному шарі, який викликає createGroup і потім addUserToGroup.
    // Для простоти, припустимо, що додавання власника як члена відбувається окремим викликом addUserToGroup
    // після успішного створення групи.

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (createGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "createGroup_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, group_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, owner_user_id);
    if (description) {
        sqlite3_bind_text(stmt, 3, description->c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3);
    }
    sqlite3_bind_int(stmt, 4, max_members);
    if (password_hash) {
        sqlite3_bind_text(stmt, 5, password_hash->c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 5);
    }
    if (salt) {
        sqlite3_bind_text(stmt, 6, salt->c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (createGroup): " << sqlite3_errmsg(db_) << std::endl;
        if (sqlite3_extended_errcode(db_) == SQLITE_CONSTRAINT_UNIQUE) {
             std::cerr << "[INFO] Group name might already exist." << std::endl;
        }
        finalize_statement(stmt, "createGroup_step", db_);
        return std::nullopt;
    } else {
        new_group_id = static_cast<int>(sqlite3_last_insert_rowid(db_));
    }

    finalize_statement(stmt, "createGroup", db_);
    // Важливо: після створення групи, власник має бути автоматично доданий до неї
    // Це можна зробити тут же, або на рівні сервісної логіки, яка викликає createGroup
    if (new_group_id != -1) {
        if (!addUserToGroup(new_group_id, owner_user_id /*, "OWNER_OR_ADMIN_ROLE" */)) {
            std::cerr << "[WARNING] Failed to add owner as member to newly created group " << new_group_id << std::endl;
            // Тут можна вирішити, чи є це критичною помилкою, що має скасувати створення групи
            // (наприклад, видалити групу або повернути std::nullopt)
        }
    }
    return new_group_id;
}

bool DatabaseManager::groupNameExists(const std::string& group_name) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT 1 FROM Groups WHERE name = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    bool exists = false;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (groupNameExists): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "groupNameExists_prepare", db_);
        return false; // Або кинути виняток
    }

    sqlite3_bind_text(stmt, 1, group_name.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        exists = true;
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (groupNameExists): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "groupNameExists", db_);
    return exists;
}

std::optional<DatabaseManager::GroupRecord> DatabaseManager::getGroupById(int group_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT id, name, password_hash, salt, owner_user_id, max_members, description, created_at, updated_at FROM Groups WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::optional<GroupRecord> groupRecord = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getGroupById): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getGroupById_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_int(stmt, 1, group_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        groupRecord = fillGroupRecordFromStatement(stmt);
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getGroupById): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getGroupById", db_);
    return groupRecord;
}

std::optional<DatabaseManager::GroupRecord> DatabaseManager::getGroupByName(const std::string& group_name) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT id, name, password_hash, salt, owner_user_id, max_members, description, created_at, updated_at FROM Groups WHERE name = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::optional<GroupRecord> groupRecord = std::nullopt;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getGroupByName): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getGroupByName_prepare", db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, group_name.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        groupRecord = fillGroupRecordFromStatement(stmt);
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getGroupByName): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getGroupByName", db_);
    return groupRecord;
}

// Для updateGroupInfo, якщо ви дозволяєте змінювати пароль, вам також потрібно передавати новий хеш та сіль.
// Або мати окремий метод updateGroupPassword. Для простоти, припустимо, пароль не змінюється тут.
bool DatabaseManager::updateGroupInfo(int group_id, const std::string& new_name, const std::optional<std::string>& new_description, int new_max_members) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // updated_at оновиться автоматично завдяки тригеру
    const char* sql = "UPDATE Groups SET name = ?, description = ?, max_members = ? WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (updateGroupInfo): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateGroupInfo_prepare", db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_name.c_str(), -1, SQLITE_STATIC);
    if (new_description) {
        sqlite3_bind_text(stmt, 2, new_description->c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 2);
    }
    sqlite3_bind_int(stmt, 3, new_max_members);
    sqlite3_bind_int(stmt, 4, group_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (updateGroupInfo): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "updateGroupInfo_step", db_);
        return false;
    }

    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "updateGroupInfo", db_);
    return success;
}

bool DatabaseManager::deleteGroup(int group_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Завдяки ON DELETE CASCADE в GroupMembers, всі члени будуть видалені
    // Але ON DELETE RESTRICT для owner_user_id в Groups може запобігти цьому,
    // якщо є інші залежності, які ви не вказали.
    // Якщо owner_user_id був SET NULL, група залишиться.
    // Перевірте логіку видалення власника!
    const char* sql = "DELETE FROM Groups WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (deleteGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "deleteGroup_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, group_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (deleteGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "deleteGroup_step", db_);
        return false;
    }

    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "deleteGroup", db_);
    return success;
}

bool DatabaseManager::addUserToGroup(int group_id, int user_id /*, const std::string& role = "MEMBER" */) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Якщо ви повернете ролі, розкоментуйте та додайте параметр role
    // const char* sql = "INSERT INTO GroupMembers (group_id, user_id, role_in_group) VALUES (?, ?, ?);";
    const char* sql = "INSERT INTO GroupMembers (group_id, user_id) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (addUserToGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "addUserToGroup_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, group_id);
    sqlite3_bind_int(stmt, 2, user_id);
    // if (role field exists) sqlite3_bind_text(stmt, 3, role.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (addUserToGroup): " << sqlite3_errmsg(db_) << std::endl;
        // Можлива помилка SQLITE_CONSTRAINT, якщо користувач вже в групі (через PK)
        finalize_statement(stmt, "addUserToGroup_step", db_);
        return false;
    }

    finalize_statement(stmt, "addUserToGroup", db_);
    return true;
}

bool DatabaseManager::removeUserFromGroup(int group_id, int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "DELETE FROM GroupMembers WHERE group_id = ? AND user_id = ?;";
    sqlite3_stmt* stmt = nullptr;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (removeUserFromGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "removeUserFromGroup_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, group_id);
    sqlite3_bind_int(stmt, 2, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (removeUserFromGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "removeUserFromGroup_step", db_);
        return false;
    }

    bool success = sqlite3_changes(db_) > 0;
    finalize_statement(stmt, "removeUserFromGroup", db_);
    return success;
}

bool DatabaseManager::isUserInGroup(int user_id, int group_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT 1 FROM GroupMembers WHERE user_id = ? AND group_id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    bool in_group = false;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (isUserInGroup): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "isUserInGroup_prepare", db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, group_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        in_group = true;
    } else if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (isUserInGroup): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "isUserInGroup", db_);
    return in_group;
}

std::vector<DatabaseManager::UserRecord> DatabaseManager::getGroupMembers(int group_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    // Нам потрібно буде JOIN з таблицею Users, щоб отримати повні дані користувачів
    const char* sql = "SELECT u.id, u.email, u.password_hash, u.salt, u.is_verified, u.vpn_ip, u.created_at, u.updated_at, u.last_login, u.status "
                      "FROM Users u JOIN GroupMembers gm ON u.id = gm.user_id "
                      "WHERE gm.group_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::vector<UserRecord> members;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getGroupMembers): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getGroupMembers_prepare", db_);
        return members; // Порожній вектор
    }

    sqlite3_bind_int(stmt, 1, group_id);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        members.push_back(fillUserRecordFromStatement(stmt)); // Використовуємо вже існуючу функцію
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getGroupMembers): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getGroupMembers", db_);
    return members;
}

std::vector<DatabaseManager::GroupRecord> DatabaseManager::getUserGroups(int user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT g.id, g.name, g.password_hash, g.salt, g.owner_user_id, g.max_members, g.description, g.created_at, g.updated_at "
                      "FROM Groups g JOIN GroupMembers gm ON g.id = gm.group_id "
                      "WHERE gm.user_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::vector<DatabaseManager::GroupRecord> groups;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getUserGroups): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getUserGroups_prepare", db_);
        return groups; // Порожній вектор
    }

    sqlite3_bind_int(stmt, 1, user_id);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        groups.push_back(fillGroupRecordFromStatement(stmt));
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getUserGroups): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getUserGroups", db_);
    return groups;
}

int DatabaseManager::getGroupMemberCount(int group_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT COUNT(user_id) FROM GroupMembers WHERE group_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    int count = 0;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getGroupMemberCount): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getGroupMemberCount_prepare", db_);
        return -1; // Помилка
    }

    sqlite3_bind_int(stmt, 1, group_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    } else if (rc != SQLITE_DONE) { // Якщо COUNT повертає 0, то це теж SQLITE_ROW
        std::cerr << "[ERROR] Failed to execute statement (getGroupMemberCount): " << sqlite3_errmsg(db_) << std::endl;
        count = -1; // Помилка
    }
    // Навіть якщо група порожня, COUNT(*) поверне 0, і rc буде SQLITE_ROW, потім SQLITE_DONE

    finalize_statement(stmt, "getGroupMemberCount", db_);
    return count;
}

std::vector<DatabaseManager::GroupRecord> DatabaseManager::getGroupsOwnedByUser(int owner_user_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    const char* sql = "SELECT id, name, password_hash, salt, owner_user_id, max_members, description, created_at, updated_at "
                      "FROM Groups WHERE owner_user_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::vector<GroupRecord> groups;

    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to prepare statement (getGroupsOwnedByUser): " << sqlite3_errmsg(db_) << std::endl;
        finalize_statement(stmt, "getGroupsOwnedByUser_prepare", db_);
        return groups; // Порожній вектор
    }

    sqlite3_bind_int(stmt, 1, owner_user_id);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        groups.push_back(fillGroupRecordFromStatement(stmt));
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to execute statement (getGroupsOwnedByUser): " << sqlite3_errmsg(db_) << std::endl;
    }

    finalize_statement(stmt, "getGroupsOwnedByUser", db_);
    return groups;
}
