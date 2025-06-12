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

class ConfigManager {
public:
    static ConfigManager& getInstance();

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void loadConfig(const std::string& filename);
    const std::map<std::string, std::any>& getConfigMap() const;

private:
    ConfigManager() {};

    bool isConfigLoaded_ = false;
    std::map<std::string, std::any> configMap_;

    void parseObj(const boost::json::object& obj, const std::string& base_key);
    //void parsePrimitive(const boost::json::value& value, std::string key);
    //void parseArray(const boost::json::array& arr, std::string key);

};
