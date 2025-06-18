//  MessageDispatcher.hpp

#pragma once

#include <QObject>

class LuminaTlsClient;

class MessageDispatcher : public QObject {
Q_OBJECT

public:
    MessageDispatcher(LuminaTlsClient *client, QObject *parent = nullptr);

signals: 

private:
    LuminaTlsClient *m_tlsClient;

private slots:
    void onMessageReceived(const QJsonObject& message);

};
