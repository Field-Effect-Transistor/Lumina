//  main_client.cpp

#include <QApplication>

#include <filesystem>

#include "AuthWindow.hpp"
#include "LuminaTlsClient.hpp"
#include "ConfigManager.hpp"
#include "MessageDispatcher.hpp"
#include "LuminaMainWindow.hpp"

//static LuminaTlsClient *client = nullptr;

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    QCoreApplication::setOrganizationName("FieldEffectTransistor");
    QCoreApplication::setApplicationName("LuminaTlsClient");

    std::string config_file_path = "";
    if (argc > 1) {
        config_file_path = argv[1];
    } else {
        std::filesystem::path executable_path(argv[0]);
        config_file_path = (executable_path.parent_path() / "config.json").string();
        if (!std::filesystem::exists(config_file_path)) {
            config_file_path = "config.json";
        }
    }

    if (!std::filesystem::exists(config_file_path)) {
        std::cerr << "Файл конфігурації не знайдено: " << config_file_path << std::endl;
        std::cerr << "Будь ласка, вкажіть шлях до файлу конфігурації як аргумент." << std::endl;
        return 1;
    }
    std::cout << "Використовується файл конфігурації: " << config_file_path << std::endl;
    ConfigManager::getInstance().loadConfig(config_file_path);

    std::string ca_path = *ConfigManager::getInstance().getValue<std::string>("tls::ca");
    auto client = LuminaTlsClient(nullptr, ca_path.c_str());
    std::string host = *ConfigManager::getInstance().getValue<std::string>("tls::host");

    MessageDispatcher dispatcher(&client);

    AuthWindow w(&dispatcher);
    LuminaMainWindow mainWindow(&dispatcher);
    //w.show();

    client.connectToServer(
        host.c_str(),
        *ConfigManager::getInstance().getValue<int64_t>("tls::port")
    );

    return a.exec();
}