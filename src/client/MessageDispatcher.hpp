//  MessageDispatcher.hpp

#pragma once

#include <QObject>

class LuminaTlsClient;

class MessageDispatcher : public QObject {
Q_OBJECT

public:
    MessageDispatcher(LuminaTlsClient *client, QObject *parent = nullptr);

private:
    LuminaTlsClient *m_tlsClient;

signals: 
    void startAuth();
    void startMainWindow();
    void authMessageReceived(const QJsonObject& message);
    void login();


public slots:
    void onMessageReceived(const QJsonObject& message);
    void onConnected();
    void onMessageSended(const QJsonObject& message);
};
