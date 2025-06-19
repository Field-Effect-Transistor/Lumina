//  LuminaTlsServer.cpp

#include "TlsSession.hpp"
#include "LuminaTlsServer.hpp"

LuminaTlsServer::LuminaTlsServer(
    net::io_context& ioc,
    ssl::context& ssl_ctx,
    unsigned short port,
    const std::string& key,
    std::shared_ptr<DatabaseManager> dbManager,
    std::shared_ptr<VpnServer> vpn 
) : m_ioc(ioc),
    m_ssl_ctx(ssl_ctx),
    m_acceptor(ioc), // Ініціалізуємо acceptor з io_context
    m_port(port),
    m_dbManager(dbManager),
    m_vpn(vpn),
    m_key(key)
{
    std::cout << "[SERVER] LuminaTlsServer created for port " << m_port << std::endl;
}

void LuminaTlsServer::run() {
    // Створюємо endpoint для прослуховування
    tcp::endpoint endpoint(tcp::v4(), m_port);

    boost::system::error_code ec;

    // Відкриваємо acceptor
    m_acceptor.open(endpoint.protocol(), ec);
    if (ec) {
        std::cerr << "[SERVER] Failed to open acceptor: " << ec.message() << std::endl;
        return; // Або кинути виняток
    }

    // (Опціонально) Встановлюємо опції для сокета acceptor'а, наприклад, reuse_address
    m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) {
        std::cerr << "[SERVER] Failed to set reuse_address option: " << ec.message() << std::endl;
        // Це може бути не критично, але варто залогувати
    }

    // Прив'язуємо acceptor до локального endpoint
    m_acceptor.bind(endpoint, ec);
    if (ec) {
        std::cerr << "[SERVER] Failed to bind acceptor to port " << m_port << ": " << ec.message() << std::endl;
        return; // Або кинути виняток
    }

    // Починаємо прослуховування вхідних з'єднань
    // Другий параметр - backlog (максимальна довжина черги очікуючих з'єднань)
    m_acceptor.listen(net::socket_base::max_listen_connections, ec);
    if (ec) {
        std::cerr << "[SERVER] Failed to listen on acceptor: " << ec.message() << std::endl;
        return; // Або кинути виняток
    }

    std::cout << "[SERVER] Server started and listening on port " << m_port << std::endl;
    // Починаємо асинхронний цикл прийому з'єднань
    do_accept();
}

void LuminaTlsServer::stop() {
    std::cout << "[SERVER] Stopping server..." << std::endl;

    // 1. Зупинити приймання нових з'єднань
    boost::system::error_code ec;
    m_acceptor.close(ec); // Закриваємо acceptor
    if (ec) {
        std::cerr << "[SERVER] Error closing acceptor: " << ec.message() << std::endl;
    }

    // 2. Закрити всі активні сесії
    // Потрібно бути обережним з ітерацією та видаленням з m_sessions одночасно,
    // особливо якщо unregister_session() викликається з іншого потоку (потоку сесії).
    // Краще створити копію списку сесій для ітерації або використовувати більш складну логіку.
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        std::cout << "[SERVER] Closing " << m_sessions.size() << " active sessions..." << std::endl;
        // Створюємо копію, бо close_socket() в сесії викличе unregister_session(),
        // що модифікує m_sessions
        auto sessions_copy = m_sessions;
        for (auto& session_ptr : sessions_copy) {

            // Якщо TlsSession::close_socket не реалізовано для виклику ззовні потоку io_context сесії:
            if (session_ptr && session_ptr->get_socket().lowest_layer().is_open()) { // Приклад методу get_socket()
                 boost::system::error_code close_ec;
                 session_ptr->get_socket().lowest_layer().shutdown(tcp::socket::shutdown_both, close_ec);
                 session_ptr->get_socket().lowest_layer().close(close_ec);
            }
        }
        m_sessions.clear(); // Очищаємо список після спроби закриття
    }
    std::cout << "[SERVER] All sessions signaled to close." << std::endl;

    // 3. Зупинка io_context (ЯКЩО LuminaTlsServer ним володіє і запускає)
    // Якщо io_context передається ззовні, то його зупинка - відповідальність зовнішнього коду.
    // if (m_ioc_owner) { // Якщо є такий прапорець
    //     m_ioc.stop();
    // }
    std::cout << "[SERVER] Server stopped." << std::endl;
}


void LuminaTlsServer::do_accept() {
    // Асинхронно очікуємо на нове з'єднання.
    // Коли з'єднання буде прийнято, буде викликано on_accept.
    // Ми передаємо лямбду, яка створює новий сокет для кожного з'єднання.
    m_acceptor.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket) {
            // Передаємо сокет в on_accept. Важливо std::move(socket).
            on_accept(ec, std::move(socket));
        }
    );
}

void LuminaTlsServer::on_accept(boost::system::error_code ec, tcp::socket socket) {
    if (ec) {
        // Якщо сталася помилка прийому (наприклад, сервер зупиняється), логуємо її.
        // Не продовжуємо цикл do_accept(), якщо помилка не тимчасова.
        if (ec != net::error::operation_aborted) { // operation_aborted - нормальна помилка при закритті acceptor'а
            std::cerr << "[SERVER] Accept error: " << ec.message() << std::endl;
        }
        // Якщо сервер зупиняється, acceptor.close() викличе operation_aborted, і ми вийдемо з циклу.
        // Якщо це інша помилка, можливо, варто спробувати продовжити приймати (але це ризиковано).
        return;
    }

    std::cout << "[SERVER] New connection accepted from: "
              << socket.remote_endpoint().address().to_string()
              << ":" << socket.remote_endpoint().port() << std::endl;

    // Створюємо нову сесію для цього з'єднання.
    // Важливо використовувати std::make_shared для правильного управління std::enable_shared_from_this.
    auto new_session = std::make_shared<TlsSession>(
        std::move(socket), // Передаємо сокет у сесію
        m_ssl_ctx,
        this // Передаємо вказівник на себе для unregister_session
    );

    register_session(new_session); // Реєструємо сесію
    new_session->start();          // Запускаємо SSL handshake та обробку в сесії

    // Продовжуємо приймати наступні з'єднання
    do_accept();
}

void LuminaTlsServer::register_session(std::shared_ptr<TlsSession> session) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.insert(session);
    std::cout << "[SERVER] Session registered. Total sessions: " << m_sessions.size() << std::endl;
}

void LuminaTlsServer::unregister_session(std::shared_ptr<TlsSession> session) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.erase(session);
    std::cout << "[SERVER] Session unregistered. Total sessions: " << m_sessions.size() << std::endl;
}
