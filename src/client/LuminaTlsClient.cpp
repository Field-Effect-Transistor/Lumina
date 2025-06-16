//  LuminaTlsClient.cpp

#include "LuminaTlsClient.hpp"
#include <QJsonDocument>
#include <QDataStream> // Для роботи з бінарними даними (заголовок довжини)
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QDebug>
#include <QtGlobal> 

LuminaTlsClient::LuminaTlsClient(QObject *parent, const QString& caFile)
    : QObject(parent),
      m_socket(new QSslSocket(this)),
      m_expectedBodySize(-1),
      m_isWriting(false),
      m_caFile(caFile)
{
    // Підключаємо сигнали сокета до наших слотів
    connect(m_socket, &QSslSocket::connected, this, &LuminaTlsClient::onConnected);
    connect(m_socket, &QSslSocket::encrypted, this, &LuminaTlsClient::onEncrypted);
    connect(m_socket, &QSslSocket::disconnected, this, &LuminaTlsClient::onDisconnected);
    connect(m_socket, &QSslSocket::readyRead, this, &LuminaTlsClient::onReadyRead);
    connect(m_socket, qOverload<const QList<QSslError>&>(&QSslSocket::sslErrors),
        this, &LuminaTlsClient::onSslErrors);
}

void LuminaTlsClient::connectToServer(const QString& host, quint16 port) {
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        qWarning() << "Socket is already connected or in progress.";
        return;
    }

    // --- Налаштування SSL ---
    // Якщо ваш сервер використовує самопідписаний сертифікат або власний CA,
    // клієнт повинен йому довіряти.
    
    // Варіант 1: Додати сертифікат вашого CA до списку довірених
    
    // ...
    // --- Налаштування SSL ---
    //QFile caFile("path/to/your/ca.crt"); // ЗАМІНІТЬ на реальний шлях
    if (m_caFile.open(QIODevice::ReadOnly)) {
        QSslCertificate caCert(&m_caFile, QSsl::Pem);
        m_caFile.close();
        
        // === ВИПРАВЛЕНИЙ БЛОК ДЛЯ СУМІСНОСТІ З УСІМА ВЕРСІЯМИ QT6 ===
        // Отримуємо об'єкт конфігурації за замовчуванням
        QSslConfiguration defaultConfig = QSslConfiguration::defaultConfiguration();
        // Отримуємо список системних CA сертифікатів з цього об'єкта
        QList<QSslCertificate> caList = defaultConfig.caCertificates();
        // === КІНЕЦЬ ВИПРАВЛЕНОГО БЛОКУ ===

        if (!caList.contains(caCert)) {
            caList.append(caCert);
            qDebug() << "Custom CA certificate added.";
        } else {
            qDebug() << "Custom CA certificate is already in the default list.";
        }

        // Отримуємо поточну конфігурацію сокета (це може бути та сама, що й defaultConfig, але для ясності краще так)
        QSslConfiguration sslConfig = m_socket->sslConfiguration();
        // Встановлюємо оновлений список довірених CA
        sslConfig.setCaCertificates(caList);
        // Застосовуємо оновлену конфігурацію до сокета
        m_socket->setSslConfiguration(sslConfig);
        
    } else {
        qWarning() << "Could not open CA certificate file:" << m_caFile.fileName();
    }

    // Варіант 2: Ігнорувати помилки SSL (ТІЛЬКИ ДЛЯ ТЕСТУВАННЯ!)
    m_socket->ignoreSslErrors();
    qWarning() << "SSL ERRORS ARE BEING IGNORED! DO NOT USE IN PRODUCTION!";
    
    qDebug() << "Connecting to" << host << ":" << port;
    m_socket->connectToHostEncrypted(host, port);
}

void LuminaTlsClient::disconnectFromServer()
{
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->disconnectFromHost();
    }
}

void LuminaTlsClient::sendMessage(const QJsonObject& message)
{
    // Серіалізуємо JSON-об'єкт в QByteArray
    QJsonDocument doc(message);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);

    // Створюємо заголовок з довжиною
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15); // Вкажіть вашу версію

    // Записуємо довжину як 32-бітне ціле число в мережевому порядку (big-endian)
    out << (quint32)jsonData.size();
    
    // Додаємо тіло повідомлення
    block.append(jsonData);

    // Додаємо в чергу на відправку
    m_writeQueue.enqueue(block);
    if (!m_isWriting) {
        doWrite(m_writeQueue.head());
    }
}

void LuminaTlsClient::onConnected()
{
    qDebug() << "TCP connection established. Waiting for encryption...";
    // Нічого не робимо, чекаємо на сигнал encrypted()
}

void LuminaTlsClient::onEncrypted()
{
    qDebug() << "TLS handshake successful. Connection is encrypted.";
    emit connected();
}

void LuminaTlsClient::onDisconnected()
{
    qDebug() << "Disconnected from server.";
    m_writeQueue.clear();
    m_isWriting = false;
    m_readBuffer.clear();
    m_expectedBodySize = -1;
    emit disconnected();
}

void LuminaTlsClient::onReadyRead()
{
    // Додаємо всі доступні дані до нашого буфера
    m_readBuffer.append(m_socket->readAll());
    processReceivedData();
}

void LuminaTlsClient::processReceivedData()
{
    while (true) {
        // Якщо ми ще не знаємо розмір тіла
        if (m_expectedBodySize == -1) {
            // Перевіряємо, чи отримали ми достатньо даних для заголовка (4 байти)
            if (m_readBuffer.size() < static_cast<int>(sizeof(quint32))) {
                return; // Недостатньо даних, чекаємо ще
            }
            // Читаємо довжину тіла з буфера
            QDataStream in(m_readBuffer.left(sizeof(quint32)));
            in.setVersion(QDataStream::Qt_5_15);
            in >> m_expectedBodySize;
            // Видаляємо заголовок з буфера
            m_readBuffer.remove(0, sizeof(quint32));
        }

        // Тепер ми знаємо очікуваний розмір тіла. Перевіряємо, чи отримали ми його повністю.
        if (m_readBuffer.size() < m_expectedBodySize) {
            return; // Недостатньо даних для тіла, чекаємо ще
        }

        // У нас є повне повідомлення. Витягуємо його.
        QByteArray jsonData = m_readBuffer.left(m_expectedBodySize);
        // Видаляємо оброблене повідомлення з буфера
        m_readBuffer.remove(0, m_expectedBodySize);

        // Скидаємо очікуваний розмір для наступного повідомлення
        m_expectedBodySize = -1;

        // Парсимо JSON
        QJsonDocument doc = QJsonDocument::fromJson(jsonData);
        if (doc.isNull() || !doc.isObject()) {
            qWarning() << "Received invalid JSON object:" << jsonData;
            continue; // Продовжуємо обробку буфера, якщо там є ще дані
        }

        // Випромінюємо сигнал з розпарсеним повідомленням
        emit messageReceived(doc.object());

        // Продовжуємо цикл, оскільки в буфері можуть бути ще повні повідомлення
    }
}


void LuminaTlsClient::onSslErrors(const QList<QSslError>& errors)
{
    QString errorStrings;
    for (const QSslError& error : errors) {
        qWarning() << "SSL Error:" << error.errorString();
        errorStrings += error.errorString() + "\n";
    }
    // Якщо ви не використовуєте ignoreSslErrors(), то з'єднання буде розірвано.
    // Тут можна показати повідомлення користувачеві.
    emit errorOccurred("SSL handshake failed: " + errorStrings);
}

void LuminaTlsClient::doWrite(const QByteArray& data)
{
    if (m_socket->state() != QAbstractSocket::ConnectedState) {
        qWarning() << "Cannot write, socket not connected.";
        m_writeQueue.clear();
        m_isWriting = false;
        return;
    }

    m_isWriting = true;
    qint64 bytesWritten = m_socket->write(data);

    if (bytesWritten == -1) {
        qWarning() << "Write error:" << m_socket->errorString();
        m_isWriting = false;
        return;
    }

    // Для TCP сокетів write() може не записати всі дані одразу.
    // Потрібно чекати сигналу bytesWritten(), щоб продовжити.
    // Або просто викликати flush().
    // Для простоти, припускаємо, що write() записує все або майже все.
    // У реальному додатку потрібна більш складна логіка з bytesWritten().
    
    // Простий варіант - чекаємо завершення запису
    if (!m_socket->waitForBytesWritten(3000)) { // Чекати 3 секунди
        qWarning() << "Write timeout or error:" << m_socket->errorString();
        m_isWriting = false;
        return;
    }

    m_writeQueue.dequeue(); // Видаляємо надіслане повідомлення
    m_isWriting = false;

    if (!m_writeQueue.isEmpty()) { // Якщо є ще що надсилати
        doWrite(m_writeQueue.head());
    }
}
