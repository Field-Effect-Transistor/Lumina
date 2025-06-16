//  LuminaTlsClient.hpp

#pragma once

#include <QObject>
#include <QSslSocket>
#include <QJsonObject> // Для роботи з JSON
#include <QQueue>      // Для черги на відправку
#include <QFile>

class LuminaTlsClient : public QObject {
    Q_OBJECT
public:
    explicit LuminaTlsClient(QObject *parent = nullptr, const QString& caFile = "");

    void connectToServer(const QString& host, quint16 port);
    void disconnectFromServer();

    // Метод для надсилання JSON-об'єкта на сервер
    void sendMessage(const QJsonObject& message);

signals:
    void connected();
    void disconnected();
    void messageReceived(const QJsonObject& message); // Сигнал, що несе розпарсений JSON
    void errorOccurred(const QString& errorString);

private slots:
    void onConnected();
    void onEncrypted(); // Рукостискання завершено
    void onDisconnected();
    void onReadyRead();
    void onSslErrors(const QList<QSslError>& errors);

private:
    void processReceivedData(); // Обробка даних з буфера
    void doWrite(const QByteArray& data); // Надсилання даних з черги

    QSslSocket* m_socket;
    QByteArray m_readBuffer; // Буфер для вхідних даних
    qint32 m_expectedBodySize; // Очікуваний розмір тіла повідомлення
    QFile m_caFile;

    QQueue<QByteArray> m_writeQueue; // Черга повідомлень на відправку
    bool m_isWriting;
};
