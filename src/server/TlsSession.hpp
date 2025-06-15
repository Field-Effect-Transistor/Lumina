//  TlsSession.hpp

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/json.hpp>
#include <memory>
#include <deque>
#include <string>
#include <optional>

static constexpr std::size_t HEADER_SIZE = 4;

#include "ValidationUtils.hpp"
#include "DatabaseManager.hpp"
class LuminaTlsServer;

namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace json = boost::json;
using tcp = boost::asio::ip::tcp;
using UserRecord = DatabaseManager::UserRecord;

class TlsSession: public std::enable_shared_from_this<TlsSession> {
public:
    TlsSession(
        tcp::socket tcp_socket,
        ssl::context& ssl_ctx,
        std::shared_ptr<DatabaseManager> database_manager,
        LuminaTlsServer* server_ptr
    );
    ~TlsSession();

    void start();
    ssl::stream<tcp::socket>& get_socket() { return m_ssl_stream; }

private:

    ssl::stream<tcp::socket> m_ssl_stream;
    beast::flat_buffer m_buffer; // Буфер для читання
    std::array<char, HEADER_SIZE> m_header_data; // Для читання заголовка (довжини повідомлення)

    std::deque<std::string> m_write_queue; // Черга рядків JSON на відправку
    bool m_is_writing = false;

    std::shared_ptr<DatabaseManager> m_dbManager;
    LuminaTlsServer* m_server_ptr;

    std::optional<UserRecord> m_currentUser;

    void do_handshake();
    void on_handshake(boost::system::error_code ec);
    void do_read_header();
    void on_read_header(boost::system::error_code ec, std::size_t bytes_transferred);
    void do_read_body(unsigned int body_length);
    void on_read_body(boost::system::error_code ec, std::size_t bytes_transferred);

    json::value handle_request(const json::value& request);
    json::value processRegisterRequest(const json::object& params);
    json::value processLoginRequest(const json::object& params);
    json::value processLogoutRequest(const json::object& params);

    void queue_write(json::value message); // Додати JSON повідомлення в чергу
    void do_write(); // Взяти з черги і відправити
    void on_write_done(boost::system::error_code ec, std::size_t bytes_transferred);

    void close_socket(boost::system::error_code ec, const std::string& reason = "");
};
