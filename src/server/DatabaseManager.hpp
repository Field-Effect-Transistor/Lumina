//  DatabaseManager.cpp

#pragma once

#include <sqlite3.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <set>
#include <ctime>
#include <mutex>

class DatabaseManager {
public:
    struct AuthTokenRecord {
        int id;
        int user_id;
        std::string token_value_hash;
        std::string token_type;
        std::string created_at;
        std::string expires_at;
        bool is_used; // У базі це INTEGER 0 або 1
    };

    struct RefreshTokenRecord {
        int id;
        int user_id;
        std::string token_hash;
        std::optional<std::string> device_info; // Може бути NULL
        std::string created_at;
        std::string expires_at;
        bool is_revoked; // У базі це INTEGER 0 або 1
        std::optional<std::string> last_used_at; // Може бути NULL
    };

    struct GroupRecord {
        int id;
        std::string name;
        std::optional<std::string> password_hash; // Може бути NULL, якщо пароль не встановлено
        std::optional<std::string> salt;          // Може бути NULL
        int owner_user_id;
        std::optional<std::string> description;   // Може бути NULL
        int max_members;
        std::string created_at;
        std::string updated_at;
    };

private:
    sqlite3* db_;
    char* zErrMsg = 0;
    int rc;
    mutable std::mutex db_mutex_;

    //  User Table Methods
    std::optional<int> getLastAssignedIpSuffix(const std::string& network_prefix);
    std::vector<int> getAllAssignedIpSuffixes(const std::string& network_prefix);

    struct UserRecord {
        int id;
        std::string email;
        std::string password_hash;
        std::string salt;
        bool is_verified; // У базі це INTEGER 0 або 1
        std::optional<std::string> vpn_ip; // Може бути NULL
        std::string created_at;
        std::string updated_at;
        std::optional<std::string> last_login; // Може бути NULL
        std::string status;
    };

    UserRecord fillUserRecordFromStatement(sqlite3_stmt* stmt);
    AuthTokenRecord fillAuthTokenRecordFromStatement(sqlite3_stmt* stmt);
    GroupRecord fillGroupRecordFromStatement(sqlite3_stmt* stmt);
    RefreshTokenRecord fillRefreshTokenRecordFromStatement(sqlite3_stmt* stmt);

public:
    DatabaseManager(const std::string& db_path);
    ~DatabaseManager();

//  Users Table Methods

    std::optional<int> addUser(
        const std::string& email,
        const std::string& password_hash,
        const std::string& salt,
        const std::string& initial_status
    );
    bool emailExists(const std::string& email);
    std::optional<UserRecord> getUserByEmail(const std::string& email);
    std::optional<UserRecord> getUserById(int user_id);
    bool updateUserPassword(
        int user_id,
        const std::string& new_password_hash,
        const std::string& new_salt
    );
    bool setUserVerified(int user_id, bool is_verified);
    bool updateUserStatus(int user_id, const std::string& new_status);
    bool updateUserLastLogin(int user_id);
    bool assignVpnIpToUser(int user_id, const std::string& vpn_ip);
    std::optional<std::string> getVpnIpForUser(int user_id);
    bool deleteUser(int user_id);
    std::optional<std::string> findFreeVpnIp(const std::string& network_prefix = "10.8.0.");

    //  AuthTokens Table Methods

    bool addAuthToken(
        int user_id,
        const std::string& token_value_hash,
        const std::string& token_type,
        int validity_seconds
    );
    std::optional<AuthTokenRecord> getValidAuthTokenByHash(
        const std::string& token_value_hash,
        const std::string& token_type
    );
    bool markAuthTokenAsUsed(const std::string& token_value_hash);
    bool invalidateUserAuthTokens(int user_id, const std::string& token_type);
    int deleteExpiredAuthTokens();

    //  RefreshTokens Table Methods

    bool addRefreshToken(
        int user_id,
        const std::string& token_hash,
        const std::string& device_info,
        int validity_seconds
    );
    std::optional<RefreshTokenRecord> getValidRefreshTokenByHash(const std::string& token_hash);
    bool revokeRefreshToken(const std::string& token_hash);
    bool revokeAllRefreshTokensForUser(int user_id);
    bool updateRefreshTokenLastUsed(const std::string& token_hash);
    int deleteExpiredOrRevokedRefreshTokens();

    //  Group Table Methods

    std::optional<int> createGroup(
        const std::string& group_name,
        int owner_user_id,
        const std::optional<std::string>& description, // Змінено на optional
        int max_members,
        const std::optional<std::string>& password_hash, // Додано
        const std::optional<std::string>& salt           // Додано
    );
    std::optional<GroupRecord> getGroupByName(const std::string& group_name);
    bool removeUserFromGroup(int user_id, int group_id);
    bool groupNameExists(const std::string& group_name);
    std::optional<GroupRecord> getGroupById(int group_id);
    bool updateGroupInfo(
        int group_id,
        const std::string& new_name,
        const std::optional<std::string>& new_description,
        int new_max_members
    );
    bool addUserToGroup(int group_id, int user_id /*, const std::string& role = "MEMBER" */);
    bool deleteGroup(int group_id);
    bool isUserInGroup(int user_id, int group_id);
    std::vector<UserRecord> getGroupMembers(int group_id);
    int getGroupMemberCount(int group_id);
    std::vector<GroupRecord> getUserGroups(int user_id);
    std::vector<GroupRecord> getGroupsOwnedByUser(int owner_user_id);

};
