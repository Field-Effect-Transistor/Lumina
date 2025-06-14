//  ConfigManager.hpp

#pragma once

#include <string>
#include <boost/json.hpp>
#include <boost/json/kind.hpp>
#include <fstream>
#include <exception>
#include <iostream>
#include <map>
#include <any>
#include <mutex>
#include <optional>

class ConfigManager {
public:
    static ConfigManager& getInstance();

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void loadConfig(const std::string& filename);
    template<typename T>
    std::optional<T> getValue(const std::string& key) const;
    
    std::map<std::string, std::any> getConfigMap() const {
        std::lock_guard<std::mutex> lock(configMutex_);
        return configMap_;
    }

private:
    ConfigManager() {};

    bool isConfigLoaded_ = false;
    std::map<std::string, std::any> configMap_;
    mutable std::mutex configMutex_;

    void parseObj(const boost::json::object& obj, const std::string& base_key);
};
