//  VpnServer.cpp

#include "VpnServer.hpp"

#include <filesystem>
#include <fstream>
#include <cstdio>
#include <memory>
#include <array>


VpnServer::VpnServer(
    const std::filesystem::path& scripts_dir,
    const std::filesystem::path& lumina_dir,
    const std::string& host,
    const std::string& server_name
): m_host(host),
   m_server_name(server_name) {
    if (!std::filesystem::exists(scripts_dir)) {
        throw std::runtime_error("Scripts directory does not exist: " + scripts_dir.string());
    }
    m_scripts_dir = scripts_dir;

    if (!std::filesystem::exists(lumina_dir)) {
        throw std::runtime_error("Lumina directory does not exist: " + lumina_dir.string());
    }
    m_lumina_dir = lumina_dir;

    startVpnServer();
}

VpnServer::~VpnServer() {
    stopVpnServer();
}

VpnServer::CommandResult VpnServer::execute(const std::string& command) const {
    std::string cmd_with_redirect = command + " 2>&1";
    std::array<char, 128> buffer;
    std::string result_output;

    FILE* pipe = popen(cmd_with_redirect.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result_output += buffer.data();
    }

    int status = pclose(pipe);

    return { WEXITSTATUS(status), result_output };
}

std::string VpnServer::sanitize(const std::string& input) const {
    std::string output = "'";
    for (char c : input) {
        if (c == '\'') {
            output += "'\\''"; // Замінюємо ' на '\''
        } else {
            output += c;
        }
    }
    output += "'";
    return output;
}

void VpnServer::startVpnServer() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_is_vpn_server_running) {
        std::cerr << "[VPN SERVER]" <<("OpenVPN server is already running.");
        return;
    }
    std::string command = "systemctl start openvpn-" + m_server_name + ".service";
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to start OpenVPN server: " + result.output);
    }
    m_is_vpn_server_running = true;
    std::cout << "[VPN SERVER]" << "OpenVPN server started." << std::endl;
}

void VpnServer::restartVpnServer() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        std::cerr << "[VPN SERVER]" <<"OpenVPN server is not running.";
    }
    std::string command = "systemctl restart openvpn-" + m_server_name + ".service";
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to restart OpenVPN server: " + result.output);
    }
    m_is_vpn_server_running = true;
    std::cout << "[VPN SERVER]" << "OpenVPN server restarted." << std::endl;
}

void VpnServer::stopVpnServer() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        std::cerr << "[VPN SERVER]" <<"OpenVPN server is not running, to be stopped" << std::endl;
        return;
    }
    std::string command = "systemctl stop openvpn-" + m_server_name + ".service";
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to stop OpenVPN server: " + result.output);
    }
    m_is_vpn_server_running = false;
    std::cout << "[VPN SERVER]" << "OpenVPN server stopped." << std::endl;
}

void VpnServer::addClient(
    const std::string& client_name,
    const std::string& client_ip
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        throw std::runtime_error("OpenVPN server is not running.");
    }
    std::string command =
        "CLIENT_NAME=" + sanitize(client_name) +
        " HOST=" + sanitize(m_host) +
        " CLIENT_IP=" + sanitize(client_ip) +
        " " + (m_scripts_dir / "add_client.sh").string();

    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to add client: " + result.output);
    }

    command = "systemctl restart openvpn-" + m_server_name + ".service";
    result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to restart OpenVPN server: " + result.output);
    }
}

void VpnServer::createGroup(
    const std::string& group_name,
    const std::string& father_ip
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        throw std::runtime_error("OpenVPN server is not running.");
    }
    
    std::string command = (m_scripts_dir / "group.sh").string() + " create " + sanitize(group_name) + " " + sanitize(father_ip);
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to create group: " + result.output);
    }
}

void VpnServer::createGroup(const std::string& group_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        throw std::runtime_error("OpenVPN server is not running.");
    }
    
    std::string command = (m_scripts_dir / "group.sh").string() + " create " + sanitize(group_name);
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to create group: " + result.output);
    }
}

void VpnServer::destroyGroup(const std::string& group_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        throw std::runtime_error("OpenVPN server is not running.");
    }
    
    std::string command = (m_scripts_dir / "group.sh").string() + " destroy " + sanitize(group_name);
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to destroy group: " + result.output);
    }
}

void VpnServer::addUserToGroup(
    const std::string& group_name,
    const std::string& user_ip
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        throw std::runtime_error("OpenVPN server is not running.");
    }
    
    std::string command = (m_scripts_dir / "group.sh").string() + " add " + sanitize(group_name) + " " + sanitize(user_ip);
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to add user to group: " + result.output);
    }
}

void VpnServer::removeUserFromGroup(
    const std::string& group_name,
    const std::string& user_ip
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_vpn_server_running) {
        throw std::runtime_error("OpenVPN server is not running.");
    }
    
    std::string command = (m_scripts_dir / "group.sh").string() + " remove " + sanitize(group_name) + " " + sanitize(user_ip);
    auto result = execute(command);
    if (result.exit_code != 0) {
        throw std::runtime_error("Failed to remove user from group: " + result.output);
    }
}

std::string VpnServer::getOvpn(const std::string& client_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (client_name.empty() || client_name.find('/') != std::string::npos || client_name.find("..") != std::string::npos) {
        throw std::runtime_error("Invalid client name provided (potential path traversal attack).");
    }

    std::filesystem::path ovpnPath = m_lumina_dir / client_name / (client_name + ".ovpn");

    auto canonical_path = std::filesystem::weakly_canonical(ovpnPath);
    auto base_path = std::filesystem::weakly_canonical(m_lumina_dir);
    if (std::string(canonical_path).find(std::string(base_path)) != 0) {
         throw std::runtime_error("Path traversal detected.");
    }

    std::ifstream file(ovpnPath);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open OVPN file for client: " + client_name);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}
