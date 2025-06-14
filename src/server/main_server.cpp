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

    auto config_map = ConfigManager::getInstance().getConfigMap();
    for (const auto& [key, value] : config_map) {
        try {
            std::cout << key << ": " << std::any_cast<std::string>(value) << std::endl;
        } catch (const std::bad_any_cast& e) {
            std::cerr << "[ConfigManager WARNING] Failed to cast config value for key '" << key << "' to requested type: " << e.what() << std::endl;
        }
    }

    std::string db_path_str;
    auto db_path_opt = ConfigManager::getInstance().getValue<std::string>("database::path"); // Виправлений ключ

    if (db_path_opt) { // Перевіряємо, чи std::optional містить значення
        db_path_str = *db_path_opt; // Розіменовуємо optional, щоб отримати значення
        std::cout << "Database path from config: " << db_path_str << std::endl;
    } else {
        db_path_str = "/etc/lumina/server/lumina.db"; // Значення за замовчуванням
        std::cout << "Database path not found in config, using default: " << db_path_str << std::endl;
    }
    // Перевірка, чи шлях не порожній перед створенням DatabaseManager (на випадок, якщо і в конфігу порожньо, і дефолтний не підходить)
    if (db_path_str.empty()) {
        std::cerr << "Critical error: Database path is empty." << std::endl;
        return 1;
    }

    DatabaseManager db(db_path_str);

    return 0;
}
