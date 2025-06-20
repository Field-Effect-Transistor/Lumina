//  TlsSession.cpp

#include "TlsSession.hpp"
#include "LuminaTlsServer.hpp"
#include "CryptoUtils.hpp"
#include "ConfigManager.hpp"

using namespace ValidationUtils;
using byte = CryptoUtils::byte;

TlsSession::TlsSession(
    tcp::socket tcp_socket,
    ssl::context& ssl_ctx,
    LuminaTlsServer* server_ptr
): m_ssl_stream(std::move(tcp_socket), ssl_ctx), // Важливо std::move для сокета
    m_dbManager(server_ptr->getDB()),
    m_vpn(server_ptr->getVpn()),
    m_server_ptr(server_ptr),
    m_is_writing(false)
{
    std::cout << "[SESSION " << this << "] New session created." << std::endl;
}

TlsSession::~TlsSession() {
    std::cout << "[SESSION " << this << "] Session destroyed." << std::endl;
    if (m_server_ptr && m_ssl_stream.lowest_layer().is_open()) { // Якщо сокет ще відкритий, а сервер існує
         std::cout << "[SESSION " << this << "] Warning: Socket was still open in destructor." << std::endl;
        // m_server_ptr->unregister_session(shared_from_this()); // Може бути небезпечно тут
    }
}

void TlsSession::start() {
    // Почати SSL handshake
    do_handshake();
}

void TlsSession::do_handshake() {
    auto self = shared_from_this(); // Захоплюємо shared_ptr для асинхронних операцій
    m_ssl_stream.async_handshake(
        ssl::stream_base::server, // Ми сервер
        [this, self](const boost::system::error_code& ec) {
            on_handshake(ec);
        }
    );
}

void TlsSession::on_handshake(boost::system::error_code ec) {
    if (ec) {
        std::cerr << "[SESSION " << this << "] Handshake failed: " << ec.message() << std::endl;
        close_socket(ec, "Handshake failed");
        return;
    }
    std::cout << "[SESSION " << this << "] Handshake successful." << std::endl;
    // Почати читання повідомлень від клієнта
    do_read_header();
}

void TlsSession::do_read_header() {
    auto self = shared_from_this();
    net::async_read(
        m_ssl_stream,
        net::buffer(m_header_data.data(), HEADER_SIZE), // Читаємо в наш буфер заголовка
        [this, self](boost::system::error_code ec, std::size_t bytes_transferred) {
            on_read_header(ec, bytes_transferred);
        }
    );
}

void TlsSession::on_read_header(boost::system::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        // EOF (End of File) або інша помилка читання - клієнт відключився або проблема
        if (ec != net::error::eof) { // EOF не завжди є "помилкою" в сенсі логування
             std::cerr << "[SESSION " << this << "] Read header failed: " << ec.message() << std::endl;
        } else {
             std::cout << "[SESSION " << this << "] Client disconnected (EOF on header)." << std::endl;
        }
        close_socket(ec, "Read header failed or client disconnected");
        return;
    }

    if (bytes_transferred != HEADER_SIZE) {
        std::cerr << "[SESSION " << this << "] Read header incomplete." << std::endl;
        close_socket(boost::system::errc::make_error_code(boost::system::errc::protocol_error), "Incomplete header");
        return;
    }

    // Припускаємо, що довжина тіла - це 4-байтне ціле число в мережевому порядку (big-endian)
    // або просто в порядку байт машини, якщо клієнт і сервер узгоджені.
    // Для прикладу, припустимо, що це uint32_t у мережевому порядку.
    uint32_t body_length_net;
    std::memcpy(&body_length_net, m_header_data.data(), HEADER_SIZE);
    uint32_t body_length = boost::endian::big_to_native(body_length_net); // Конвертуємо в порядок байт машини

    // Перевірка на максимальний розмір повідомлення
    if (body_length > 65536) { // Приклад обмеження (64KB)
        std::cerr << "[SESSION " << this << "] Message body too large: " << body_length << std::endl;
        close_socket(boost::system::errc::make_error_code(boost::system::errc::value_too_large), "Message too large");
        return;
    }
    if (body_length == 0) { // Якщо тіло порожнє, можливо, це ping або щось ще
        std::cout << "[SESSION " << this << "] Received header for empty body. Reading next header." << std::endl;
        do_read_header(); // Готові читати наступний заголовок
        return;
    }

    // std::cout << "[SESSION " << this << "] Header received, body length: " << body_length << std::endl;
    do_read_body(body_length);
}

void TlsSession::do_read_body(unsigned int body_length) {
    auto self = shared_from_this();
    // Гарантуємо, що буфер може вмістити body_length байт
    m_buffer.clear(); // Очистити попередні дані
    // m_buffer.reserve(body_length); // Це може не бути потрібно для flat_buffer так

    net::async_read(
        m_ssl_stream,
        m_buffer.prepare(body_length), // Готуємо місце в буфері
        [this, self, body_length](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (!ec) {
                m_buffer.commit(bytes_transferred); // Робимо прочитані дані доступними
            }
            on_read_body(ec, bytes_transferred);
        }
    );
}

void TlsSession::on_read_body(boost::system::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        if (ec != net::error::eof) {
             std::cerr << "[SESSION " << this << "] Read body failed: " << ec.message() << std::endl;
        } else {
             std::cout << "[SESSION " << this << "] Client disconnected (EOF on body)." << std::endl;
        }
        close_socket(ec, "Read body failed or client disconnected");
        return;
    }

    // Конвертуємо вміст буфера в рядок
    // beast::buffers_to_string() може бути корисним, або:
    std::string body_str(static_cast<const char*>(m_buffer.data().data()), bytes_transferred);
    m_buffer.consume(bytes_transferred); // Видаляємо оброблені дані з буфера

    // std::cout << "[SESSION " << this << "] Body received: " << body_str << std::endl;

    // Парсимо JSON
    boost::system::error_code parse_ec;
    json::value request_json = json::parse(body_str, parse_ec);

    if (parse_ec) {
        std::cerr << "[SESSION " << this << "] JSON parse error: " << parse_ec.message() << std::endl;
        // Можливо, надіслати помилку клієнту
        json::value error_response = {{"status", "error"}, {"message", "Invalid JSON format"}};
        queue_write(std::move(error_response));
        do_read_header(); // Готові до наступного повідомлення
        return;
    }

    // Обробляємо запит
    json::value response_json = handle_request(request_json);

    // Надсилаємо відповідь
    if (!response_json.is_null()) { // Надсилаємо відповідь, тільки якщо вона є
        queue_write(std::move(response_json));
    }

    // Продовжуємо читати наступний заголовок
    do_read_header();
}

// Приклад диспетчера запитів
json::value TlsSession::handle_request(const json::value& request) {
    if (!request.is_object()) {
        return {{"status", "error"}, {"message", "Request must be a JSON object"}};
    }
    const json::object& req_obj = request.as_object();

    if (!req_obj.contains("command") || !req_obj.at("command").is_string()) {
        return {{"status", "error"}, {"message", "Missing or invalid 'command' field"}};
    }

    std::cout << "[SESSION " << this << "] Received request: " << request << std::endl;

    std::string command = json::value_to<std::string>(req_obj.at("command"));
    json::object params; // Параметри для команди
    if (req_obj.contains("params") && req_obj.at("params").is_object()) {
        params = req_obj.at("params").as_object();
    }

    std::cout << "[SESSION " << this << "] Received command: " << command << std::endl;


    if (command == "register") {
        return processRegisterRequest(params);
    } else if (command == "login") {
        return processLoginRequest(params);
    } else if (command == "logout") {
        //return processLogoutRequest(params);
    } else if (command == "restoreSession") {
        return processRestoreSessionRequest(params);
    } else if (command == "getGroups") {
        return processGetGroupsRequest(params);
    } else if (command == "ovpn") {
        return processOvpnRequest(params);
    }
    return {{"status", "error"}, {"message", "Unknown command: " + command}};
}

// Приклад обробника реєстрації (дуже спрощено)
json::value TlsSession::processRegisterRequest(const json::object& params) {
    try {
        //  validate params
        if (
            !params.contains("username") || !params.at("username").is_string() ||
            !params.contains("password") || !params.at("password").is_string()
        ) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "Missing or invalid 'username' or 'password' field"}};
        }

        std::string username = json::value_to<std::string>(params.at("username"));
        std::string password = json::value_to<std::string>(params.at("password"));

        ValidationResult result = validateEmail(username);
        if (result.has_value()) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", result->message}};
        }

        result = validatePassword(password);
        if (result.has_value()) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", result->message}};
        }

        //  check is user exist
        auto user = m_dbManager->getUserByEmail(username);
        if (user.has_value()) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "User already exists"}};
        }
        //  hash password
        std::vector<byte> salt = CryptoUtils::saltBin();
        std::vector<byte> hash = CryptoUtils::hashPassword(password, salt);
        std::string salt_hex = CryptoUtils::bin2hex(salt);
        std::string hash_hex = CryptoUtils::bin2hex(hash);

        //  create user
        auto user_id = m_dbManager->addUser(username, hash_hex, salt_hex, "ACTIVE");
        if (!user_id.has_value()) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "Failed to create user"}};
        }

        //  send activation email
        //! TODO
        if (!m_dbManager->setUserVerified(user_id.value(), true)) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "Failed to set user as verified"}};
        }

        //  set vpn ip
        auto ip_prefix_ = ConfigManager::getInstance().getValue<std::string>("vpnserver::network_prefix");
        if (!ip_prefix_.has_value()) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "Failed to set user as verified"}};
        }
        auto ip = m_dbManager->findFreeVpnIp(*ip_prefix_);
        if (!ip.has_value()) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "Failed to set user as verified"}};
        }
        if (!m_dbManager->assignVpnIpToUser(user_id.value(), *ip)) {
            return {{"responseTo", "register"}, {"status", "error"}, {"message", "Failed to set user as verified"}};
        }

        // Creating new vpn client
        m_vpn->addClient(username, *ip);
    }
    catch (const std::exception& e) {
        std::cerr << "[SESSION " << this << "] Failed to create user: " << e.what() << std::endl;
        return {{"responseTo", "register"}, {"status", "error"}, {"message", "Failed to create user: " + std::string(e.what())}};
    }

    return {{"status", "success"}, {"message", "Registration request received (implement actual logic)"}};
}

json::value TlsSession::processLoginRequest(const json::object& params) {
    try {
        //  validate params
        if (
            !params.contains("username") || !params.at("username").is_string() ||
            !params.contains("password") || !params.at("password").is_string()
        ) {
            return {{"responseTo", "login"}, {"status", "error"}, {"message", "Missing or invalid 'username' or 'password' field"}};    
        }

        std::string username = json::value_to<std::string>(params.at("username"));
        std::string password = json::value_to<std::string>(params.at("password"));

        ValidationResult result = validateEmail(username);
        if (result.has_value()) {
            return {{"responseTo", "login"}, {"status", "error"}, {"message", result->message}};
        }

        result = validatePassword(password);
        if (result.has_value()) {
            return {{"responseTo", "login"}, {"status", "error"}, {"message", result->message}};
        }

        //  check cridentals
        auto user = m_dbManager->getUserByEmail(username);
        if (!user.has_value()) {
            return {{"responseTo", "login"}, {"status", "error"}, {"message", "User not found"}};
        }

        if (!CryptoUtils::verifyPassword(
            password,
            user->salt,
            user->password_hash
        )) {
            return {{"responseTo", "login"}, {"status", "error"}, {"message", "Invalid password"}};
        }

        m_currentUser = user.value();

        auto refreshToken = CryptoUtils::generateTokenBase64();
        auto accessToken = CryptoUtils::generateAccessTokenBase64(
            {
                {"user_id", m_currentUser.id},
                {"email", m_currentUser.email},
                {"iat", getCurrentTimestamp()},
                {"exp", getFutureTimestamp(30 * 60)}
            },
            m_server_ptr->m_key
        );

        auto refreshTokenHash = CryptoUtils::bin2hex(
            CryptoUtils::hashTokenBin(refreshToken)
        );
        m_dbManager->addRefreshToken(
            m_currentUser.id,
            refreshTokenHash,
            "none",
            TlsSession::refreshTokenLifetime
        );

        std::cout << "[SESSION " << this << "] Login successful. ONLY FOR TESTING!!!" << std::endl;
        std::cout << "[SESSION " << this << "] Refresh token: " << refreshToken << std::endl;
        std::cout << "[SESSION " << this << "] Access token: " << accessToken << std::endl;

        return {
            {"status", "success"},
            {"responseTo", "login"},
            {"refreshToken", refreshToken},
            {"accessToken", accessToken}
        };


    } catch (const std::exception& e) {
        std::cerr << "[SESSION " << this << "] Failed to login: " << e.what() << std::endl;
        return {{"responseTo", "login"}, {"status", "error"}, {"message", "Failed to login: " + std::string(e.what())}};
    }
    return {{"status", "success"}, {"message", "Login request received (implement actual logic)"}};
}

json::value TlsSession::processRestoreSessionRequest(const json::object& params) {
    try {
        //  validate params
        if (
            !params.contains("refreshToken") || !params.at("refreshToken").is_string()
        ) {
            return {{"responseTo", "restoreSession"}, {"status", "error"}, {"message", "Missing or invalid 'refreshToken' field"}};    
        }

        std::string refreshToken = json::value_to<std::string>(params.at("refreshToken"));

        auto refreshTokenHash = CryptoUtils::bin2hex(
            CryptoUtils::hashTokenBin(refreshToken)
        );

        auto token = m_dbManager->getValidRefreshTokenByHash(refreshTokenHash);
        if (!token.has_value()) {
            return {{"responseTo", "restoreSession"}, {"status", "error"}, {"message", "Invalid refresh token"}};
        }

        auto user = m_dbManager->getUserById(token->user_id);
        if (!user.has_value()) {
            return {{"responseTo", "restoreSession"}, {"status", "error"}, {"message", "User not found"}};
        }

        m_currentUser = user.value();

        auto accessToken = CryptoUtils::generateAccessTokenBase64(
            {
                {"user_id", m_currentUser.id},
                {"email", m_currentUser.email},
                {"iat", getCurrentTimestamp()},
                {"exp", getFutureTimestamp(30 * 60)}
            },
            m_server_ptr->m_key
        );

        return {
            {"responseTo", "restoreSession"},
            {"status", "success"},
            {"accessToken", accessToken},
            //{"username", m_currentUser.email}
        };

    } catch (const std::exception& e) {
        std::cerr << "[SESSION " << this << "] Failed to restore session: " << e.what() << std::endl;
        return {{"responseTo", "restoreSession"}, {"status", "error"}, {"message", "Failed to restore session: " + std::string(e.what())}};
    }
}

json::value TlsSession::processGetGroupsRequest(const json::object& params) {
    try {
        //  validate params
        if (
            !params.contains("accessToken") || !params.at("accessToken").is_string()
        ) {
            return {{"responseTo", "getGroups"}, {"status", "error"}, {"message", "Missing or invalid 'accessToken' field"}};    
        }

        std::string accessToken = json::value_to<std::string>(params.at("accessToken"));
        auto payload = CryptoUtils::validateAccessTokenBase64(
            accessToken,
            m_server_ptr->m_key    
        );

        if (!payload.has_value()) {
            return {{"responseTo", "getGroups"}, {"status", "error"}, {"message", "Invalid access token"}};
        }

        if (
            payload->at("exp").as_int64() < getCurrentTimestamp() &&
            payload->at("user_id").as_int64() != m_currentUser.id
        ) {
            return {
                {"responseTo", "any"},
                {"status", "updateAccessToken"},
                {"request", {"command", "getGroups"}}
            };
        }

        auto userGroups = m_dbManager->getUserGroups(m_currentUser.id);
        boost::json::array groups;
        for (const auto& group : userGroups) {
            boost::json::object group_obj;
            group_obj["id"] = group.id;
            group_obj["name"] = group.name;
            auto members = m_dbManager->getGroupMembers(group.id);
            boost::json::array members_array;
            for (const auto& member : members) {
                boost::json::object member_obj;
                member_obj["id"] = member.id;
                member_obj["name"] = member.email;
                member_obj["ip"] = *member.vpn_ip;
                members_array.push_back(member_obj);
            }
            group_obj["members"] = members_array;
            groups.push_back(group_obj);
        }

        return {
            {"responseTo", "getGroups"},
            {"status", "success"},
            {"groups", groups}
        };

    } catch (const std::exception& e) {
        std::cerr << "[SESSION " << this << "] Failed to get groups: " << e.what() << std::endl;
        return {{"responseTo", "getGroups"}, {"status", "error"}, {"message", "Failed to get groups: " + std::string(e.what())}};
    }
}

json::value TlsSession::processOvpnRequest(const json::object& params) {
    try {
        if (
            !params.contains("accessToken") || !params.at("accessToken").is_string()
        ) {
            return {{"responseTo", "ovpn"}, {"status", "error"}, {"message", "Missing or invalid 'accessToken' field"}};    
        }

        std::string accessToken = json::value_to<std::string>(params.at("accessToken"));
        auto payload = CryptoUtils::validateAccessTokenBase64(
            accessToken,
            m_server_ptr->m_key    
        );

        if (!payload.has_value()) {
            return {{"responseTo", "ovpn"}, {"status", "error"}, {"message", "Invalid access token"}};
        }

        if (
            payload->at("exp").as_int64() < getCurrentTimestamp() &&
            payload->at("user_id").as_int64() != m_currentUser.id
        ) {
            return {
                {"responseTo", "any"},
                {"status", "updateAccessToken"},
                {"request", {"command", "ovpn"}}
            };
        }

        auto ovpn = m_vpn->getOvpn(m_currentUser.email);

        return {
            {"responseTo", "ovpn"},
            {"status", "success"},
            {"ovpn", ovpn}
        };
        
    } catch(const std::exception& e) {
        std::cerr << "[SESSION " << this << "] Failed to process ovpn request: " << e.what() << std::endl;
        return {{"responseTo", "ovpn"}, {"status", "error"}, {"message", "Failed to process ovpn request: " + std::string(e.what())}};
    }
}

void TlsSession::queue_write(json::value message) {
    // Серіалізуємо JSON у рядок
    std::string message_str = json::serialize(message);

    // Формуємо повне повідомлення з заголовком довжини
    uint32_t body_length = static_cast<uint32_t>(message_str.length());
    uint32_t body_length_net = boost::endian::native_to_big(body_length); // Конвертуємо в мережевий порядок

    std::string full_message_to_send;
    full_message_to_send.resize(HEADER_SIZE + body_length);
    std::memcpy(&full_message_to_send[0], &body_length_net, HEADER_SIZE);
    std::memcpy(&full_message_to_send[HEADER_SIZE], message_str.data(), body_length);

    // Додаємо в чергу
    // Потрібно подбати про потокобезпечність, якщо queue_write може викликатися з різних потоків,
    // хоча в типовій моделі Asio з одним io_context::run() на потік це не проблема для однієї сесії.
    // Для простоти, припускаємо, що всередині сесії доступ до черги синхронізований.
    bool write_in_progress = !m_write_queue.empty(); // Або краще використовувати m_is_writing
    m_write_queue.push_back(std::move(full_message_to_send));

    if (!m_is_writing) { // Якщо запис не триває, починаємо його
        do_write();
    }
}

void TlsSession::do_write() {
    if (m_write_queue.empty()) {
        m_is_writing = false;
        return;
    }
    m_is_writing = true;
    auto self = shared_from_this();

    net::async_write(
        m_ssl_stream,
        net::buffer(m_write_queue.front().data(), m_write_queue.front().length()),
        [this, self](boost::system::error_code ec, std::size_t bytes_transferred) {
            on_write_done(ec, bytes_transferred);
        }
    );
}

void TlsSession::on_write_done(boost::system::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        std::cerr << "[SESSION " << this << "] Write failed: " << ec.message() << std::endl;
        close_socket(ec, "Write failed");
        return;
    }

    m_write_queue.pop_front(); // Видаляємо надіслане повідомлення з черги
    m_is_writing = false;      // Позначаємо, що запис завершено

    if (!m_write_queue.empty()) { // Якщо в черзі є ще повідомлення
        do_write(); // Продовжуємо запис
    }
}

void TlsSession::close_socket(boost::system::error_code original_ec, const std::string& reason) {
    if (!m_ssl_stream.lowest_layer().is_open()) {
        // Вже закрито або ніколи не було відкрито
        if (m_server_ptr) { // Все одно сповістити сервер, якщо він є
             m_server_ptr->unregister_session(shared_from_this());
        }
        return;
    }

    std::cout << "[SESSION " << this << "] Closing socket. Reason: " << reason
              << (original_ec ? " (Error: " + original_ec.message() + ")" : "") << std::endl;

    auto self = shared_from_this(); // Для лямбди async_shutdown

    // Асинхронно закриваємо SSL шар
    m_ssl_stream.async_shutdown(
        [this, self](const boost::system::error_code& ec_shutdown) {
            // Неважливо, чи була помилка при shutdown, ми все одно закриваємо TCP сокет
            if (ec_shutdown && ec_shutdown != net::error::eof && ec_shutdown != ssl::error::stream_truncated) {
                // ssl::error::stream_truncated може виникати, якщо клієнт просто закрив з'єднання
                std::cerr << "[SESSION " << this << "] SSL shutdown error: " << ec_shutdown.message() << std::endl;
            }

            boost::system::error_code ec_close;
            m_ssl_stream.lowest_layer().close(ec_close); // Закриваємо TCP сокет
            if (ec_close) {
                std::cerr << "[SESSION " << this << "] TCP socket close error: " << ec_close.message() << std::endl;
            }

            // Повідомляємо головний сервер, що сесія завершена
            if (m_server_ptr) {
                m_server_ptr->unregister_session(self);
            }
        }
    );
}
