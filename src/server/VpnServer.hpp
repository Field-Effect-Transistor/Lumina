//  VpnServer.hpp

#pragma once

#include <iostream>
#include <filesystem>
#include <mutex>

class VpnServer {
public:
    VpnServer(
        const std::filesystem::path& scripts_dir,
        const std::filesystem::path& lumina_dir,
        const std::string& host,
        const std::string& server_name
    );
    ~VpnServer();

    mutable std::mutex m_mutex;
    bool m_is_vpn_server_running = false;
    std::filesystem::path m_scripts_dir;
    std::filesystem::path m_lumina_dir;
    std::string m_host;
    std::string m_server_name;

    void startVpnServer();
    void restartVpnServer();
    void stopVpnServer();

    void addClient(
        const std::string& client_name,
        const std::string& client_ip
    );
    //void removeClient(const std::string& client_ip);
    std::string getOvpn(const std::string& client_name);

    void createGroup(const std::string& group_name, const std::string& father_ip);
    void createGroup(const std::string& group_name);
    void destroyGroup(const std::string& group_name);
    
    void addUserToGroup(const std::string& group_name, const std::string& user_ip);
    void removeUserFromGroup(const std::string& group_name, const std::string& user_ip);

    struct CommandResult {
        int exit_code;
        std::string output;
    };

private:
    CommandResult execute(const std::string& command) const;
    std::string sanitize(const std::string& input) const;
}; 
