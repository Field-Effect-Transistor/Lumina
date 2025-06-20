//  MessageDispatcher.hpp

#pragma once

#include <QObject>
#include <QJsonObject>

#include <optional>

class LuminaTlsClient;

class MessageDispatcher : public QObject {
Q_OBJECT

public:
    MessageDispatcher(LuminaTlsClient *client, QObject *parent = nullptr);

private:
    LuminaTlsClient *m_tlsClient;

    std::optional<QJsonObject> m_lastRequest;

signals: 
    void startAuth();
    //void startMainWindow();
    void authMessageReceived(const QJsonObject& message);
    void mainMessageReceived(const QJsonObject& message);
    void loginSuccess();
    void disconnected();


public slots:
    void onMessageReceived(const QJsonObject& message);
    void onConnected();
    void onMessageSended(const QJsonObject& message);
    void onDisconnected();
};
