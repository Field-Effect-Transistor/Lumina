//  MessageDispatcher.cpp

#include "MessageDispatcher.hpp"
#include "LuminaTlsClient.hpp"

#include <QMessageBox>
#include <QSettings>

MessageDispatcher::MessageDispatcher(LuminaTlsClient *client, QObject *parent)
    : QObject(parent),
    m_tlsClient(client) {
    connect(m_tlsClient, &LuminaTlsClient::messageReceived, this, &MessageDispatcher::onMessageReceived);
}
    
void MessageDispatcher::onMessageReceived(const QJsonObject& message) {
    qDebug() << "Received message:" << message;
    
    QString status = message["status"].toString();
    if (status == "success") {
        QString command = message["command"].toString();
        if (command == "login") {
            QSettings settings;
            if (message.contains("accessToken")) {
                settings.setValue("accessToken", message["accessToken"].toString());
            }
            if (message.contains("refreshToken")) {
                settings.setValue("refreshToken", message["refreshToken"].toString());
            }
            emit login(message);
        }
    } else {
        QMessageBox::critical(nullptr, "Error", message["message"].toString());
    }
}
