// main_server.cpp
#include <iostream>
#include <filesystem>
#include <string>
#include <cstdint> // Для uint16_t
#include <optional> // Для std::optional
#include <vector>
#include <thread>

#include "ConfigManager.hpp" // Припускаємо, що він існує і працює
#include "DatabaseManager.hpp"
#include "LuminaTlsServer.hpp"
#include "CryptoUtils.hpp"
#include "VpnServer.hpp"

#include <boost/asio/signal_set.hpp>


int main(int argc, char *argv[]) {
    CryptoUtils::init();

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
    // --- Отримання шляху до БД ---
    std::optional<std::string> db_path_opt = ConfigManager::getInstance().getValue<std::string>("database::path");
    std::string db_path_str;
    if (db_path_opt) {
        db_path_str = *db_path_opt;
    } else {
        std::cerr << "Критична помилка: шлях до бази даних ('database.path') не знайдено в конфігурації." << std::endl;
        return 1;
    }
    if (db_path_str.empty()) {
        std::cerr << "Критична помилка: шлях до бази даних порожній у конфігурації." << std::endl;
        return 1;
    }
    std::cout << "Шлях до БД: " << db_path_str << std::endl;

    auto dbManager = std::make_shared<DatabaseManager>(db_path_str);

    auto port_opt = ConfigManager::getInstance().getValue<int64_t>("tls::port");
    std::optional<std::string> cert_path_opt = ConfigManager::getInstance().getValue<std::string>("tls::cert");
    std::optional<std::string> key_path_opt = ConfigManager::getInstance().getValue<std::string>("tls::key");

    if (!port_opt || !cert_path_opt || !key_path_opt) {
        std::cerr << "Критична помилка: відсутні параметри TLS (port, cert, key) у конфігурації." << std::endl;
        return 1;
    }
    uint16_t port = static_cast<uint16_t>(*port_opt);
    std::string cert_path = *cert_path_opt;
    std::string key_path = *key_path_opt;

    std::cout << "Порт TLS: " << port << std::endl;
    std::cout << "Шлях до сертифіката: " << cert_path << std::endl;
    std::cout << "Шлях до ключа: " << key_path << std::endl;

    try {
        auto scripts_dir = ConfigManager::getInstance().getValue<std::string>("vpnserver::scripts_dir");
        auto lumina_dir = ConfigManager::getInstance().getValue<std::string>("lumina_dir");
        auto host = ConfigManager::getInstance().getValue<std::string>("vpnserver::host");
        auto server_name = ConfigManager::getInstance().getValue<std::string>("vpnserver::server_name");
        auto vpn = std::make_shared<VpnServer>(
            *scripts_dir,
            *lumina_dir,
            *host,
            *server_name
        );

        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 2;
        net::io_context ioc; // Створюємо io_context один раз

        ssl::context ssl_ctx(ssl::context::tls_server);
        ssl_ctx.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            ssl::context::no_sslv3 |
            ssl::context::single_dh_use
        );

        boost::system::error_code ec_ssl;
        ssl_ctx.use_certificate_chain_file(cert_path, ec_ssl);
        if(ec_ssl) { std::cerr << "SSL_CTX: Помилка завантаження ланцюжка сертифікатів: " << ec_ssl.message() << std::endl; return 1; }

        ssl_ctx.use_private_key_file(key_path, ssl::context::pem, ec_ssl);
        if(ec_ssl) { std::cerr << "SSL_CTX: Помилка завантаження приватного ключа: " << ec_ssl.message() << std::endl; return 1; }
        
        ssl_ctx.set_verify_mode(ssl::verify_none, ec_ssl); // Клієнтський сертифікат не потрібен
        if(ec_ssl) { std::cerr << "SSL_CTX: Помилка встановлення режиму верифікації: " << ec_ssl.message() << std::endl; return 1; }


        auto server = std::make_shared<LuminaTlsServer>(ioc, ssl_ctx, port, dbManager, vpn);
        server->run();

        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait(
            [&server, &ioc](const boost::system::error_code& /*error*/, int signal_number) {
                std::cout << "\nСигнал " << signal_number << " отримано. Зупинка сервера..." << std::endl;
                // Спочатку просимо сервер зупинити приймання нових і закрити існуючі сесії
                if (server) server->stop();
                // Потім зупиняємо io_context, щоб всі потоки run() завершилися
                ioc.stop();
            }
        );
        std::cout << "Сервер запущено. Натисніть Ctrl+C для зупинки." << std::endl;

        std::vector<std::thread> threads;
        for (unsigned int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&ioc]() {
                try {
                    ioc.run();
                } catch (const std::exception& e) {
                    std::cerr << "Виняток у потоці io_context: " << e.what() << std::endl;
                }
            });
        }

        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        std::cout << "Сервер зупинено." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Виняток у main: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}