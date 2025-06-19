//  LuminaTlsServer.hpp

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <string>
#include <set> // Для зберігання сесій
#include <mutex> // Для захисту списку сесій

// Forward declarations
//#include "TlsSession.hpp"
class TlsSession;
#include "DatabaseManager.hpp"
#include "VpnServer.hpp"

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

class LuminaTlsServer : public std::enable_shared_from_this<LuminaTlsServer> {
public:
    LuminaTlsServer(
        net::io_context& ioc,
        ssl::context& ssl_ctx,
        unsigned short port,
        const std::string& key,
        std::shared_ptr<DatabaseManager> dbManager,
        std::shared_ptr<VpnServer> vpn
    );

    void run();
    void stop();

    // Методи для управління списком сесій (якщо потрібно)
    void register_session(std::shared_ptr<TlsSession> session);
    void unregister_session(std::shared_ptr<TlsSession> session);

    std::shared_ptr<DatabaseManager> getDB() { return m_dbManager; }
    std::shared_ptr<VpnServer> getVpn() { return m_vpn; }

    std::string m_key;

private:
    void do_accept();
    void on_accept(boost::system::error_code ec, tcp::socket socket);

    net::io_context& m_ioc;
    ssl::context& m_ssl_ctx;
    tcp::acceptor m_acceptor;
    unsigned short m_port;

    std::shared_ptr<DatabaseManager> m_dbManager;
    std::shared_ptr<VpnServer> m_vpn;

    std::mutex m_sessions_mutex; // М'ютекс для захисту m_sessions
    std::set<std::shared_ptr<TlsSession>> m_sessions; // Активні сесії
};