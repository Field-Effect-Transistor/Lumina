//  main_server.cpp

#include <iostream>
#include <filesystem>
#include <string>
#include <cstdint>

#include "ConfigManager.hpp"
#include "DatabaseManager.hpp"

int main(int argc, char *argv[]) {
    std::string config_file_path = "";
    if (argc == 1) {
        config_file_path = std::filesystem::current_path().string() + "/config.json";
    } else {
        config_file_path = argv[1];
    }

    if (std::filesystem::exists(config_file_path)) {
        std::cout << "Config file found: " << config_file_path << std::endl;
    } else {
        std::cout << "Config file not found: " << config_file_path << std::endl;
        return 1;
    }

    ConfigManager::getInstance().loadConfig(config_file_path);
    const auto& config_map = ConfigManager::getInstance().getConfigMap();
    for (const auto& pair : config_map) {
        std::cout << pair.first << ": ";
        if (pair.second.type() == typeid(std::string)) {
            std::cout << std::any_cast<std::string>(pair.second) << std::endl;
        } else if (pair.second.type() == typeid(int64_t)) {
            std::cout << std::any_cast<int64_t>(pair.second) << std::endl;
        } else if (pair.second.type() == typeid(double)) {
            std::cout << std::any_cast<double>(pair.second) << std::endl;
        } else if (pair.second.type() == typeid(bool)) {
            std::cout << std::any_cast<bool>(pair.second) << std::endl;
        }
    }

    DatabaseManager db(std::any_cast<std::string>(config_map.at("database::path")));

    return 0;
}
