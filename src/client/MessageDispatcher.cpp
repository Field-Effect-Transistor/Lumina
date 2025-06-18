//  MessageDispatcher.cpp

#include "MessageDispatcher.hpp"
#include "LuminaTlsClient.hpp"

MessageDispatcher::MessageDispatcher(LuminaTlsClient *client, QObject *parent)
    : QObject(parent),
    m_tlsClient(client) {
    connect(m_tlsClient, &LuminaTlsClient::messageReceived, this, &MessageDispatcher::onMessageReceived);
}
    
void MessageDispatcher::onMessageReceived(const QJsonObject& message) {
    qDebug() << "Received message:" << message;
}
