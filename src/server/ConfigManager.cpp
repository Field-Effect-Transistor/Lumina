// ConfigManager.cpp

#include "ConfigManager.hpp"
#include <boost/json/value_to.hpp> // Для boost::json::value_to

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

void ConfigManager::loadConfig(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        // Краще кидати виняток або повертати false і обробляти це
        std::cerr << "Error: Could not open config file: " << filename << std::endl;
        isConfigLoaded_ = false; // Явно вказати, що завантаження не вдалося
        // throw std::runtime_error("Failed to open config file: " + filename); // Альтернатива
        return;
    }

    configMap_.clear(); // Очистити перед новим завантаженням
    isConfigLoaded_ = false;

    try {
        boost::json::value config = boost::json::parse(file); // Парсимо весь файл
        file.close(); // Закриваємо файл після читання

        if (config.is_object()) {
            parseObj(config.as_object(), ""); // Початковий base_key порожній
            isConfigLoaded_ = true; // Встановлюємо прапорець успішного завантаження
        } else {
            std::cerr << "Error: Root of JSON config is not an object." << std::endl;
            // throw std::runtime_error("Invalid JSON format: Root is not an object");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing JSON from file '" << filename << "': " << e.what() << std::endl;
        // isConfigLoaded_ залишається false
        // throw; // Можна перекинути виняток далі, якщо потрібно
    }

    isConfigLoaded_ = true;
    file.close();
}

void ConfigManager::parseObj(const boost::json::object& obj, const std::string& base_key) {
    for (const auto& pair : obj) {
        std::string current_key;
        if (base_key.empty()) {
            current_key = pair.key_c_str();
        } else {
            current_key = base_key + "::" + pair.key_c_str();
        }

        const auto& value = pair.value(); // Зберігаємо значення для зручності

        if (value.is_object()) {
            parseObj(value.as_object(), current_key);
        } else if (value.is_string()) {
            configMap_[current_key] = boost::json::value_to<std::string>(value); // ВИПРАВЛЕНО
        } else if (value.is_int64()) {
            configMap_[current_key] = value.as_int64(); // ВИПРАВЛЕНО
        } else if (value.is_uint64()) { // Додано для повноти
            configMap_[current_key] = value.as_uint64(); // ВИПРАВЛЕНО
        } else if (value.is_double()) {
            configMap_[current_key] = value.as_double(); // ВИПРАВЛЕНО
        } else if (value.is_bool()) {
            configMap_[current_key] = value.as_bool(); // ВИПРАВЛЕНО
        } else if (value.is_array()) {
            throw std::runtime_error("Array found at key '" + current_key + "' - storing as raw boost::json::array.");
            configMap_[current_key] = value.as_array(); // Потрібно буде обробляти цей тип при отриманні
        } else if (value.is_null()) {
            configMap_[current_key] = nullptr;
        }
    }
}

const std::map<std::string, std::any>& ConfigManager::getConfigMap() const {
    if (!isConfigLoaded_) {
        throw "Config not loaded";
    }
    return configMap_;
}
