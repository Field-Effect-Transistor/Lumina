//  MessageDispatcher.cpp

#include "MessageDispatcher.hpp"
#include "LuminaTlsClient.hpp"

#include <QSettings>

MessageDispatcher::MessageDispatcher(LuminaTlsClient *client, QObject *parent)
    : QObject(parent),
    m_tlsClient(client) {
    connect(m_tlsClient, &LuminaTlsClient::messageReceived, this, &MessageDispatcher::onMessageReceived);
    connect(m_tlsClient, &LuminaTlsClient::connected, this, &MessageDispatcher::onConnected);
}
    
void MessageDispatcher::onConnected() {
    QSettings settings;
    auto refreshToken = settings.value("refreshToken");
    auto username = settings.value("username");
    if (refreshToken.isNull() && username.isNull()) {
        emit startAuth();
    } else {
        QJsonObject request;
        request["command"] = "restoreSession";
        QJsonObject params;
        params["refreshToken"] = refreshToken.toString();
        request["params"] = params;
        m_tlsClient->sendMessage(request);
    }
}

void MessageDispatcher::onMessageReceived(const QJsonObject& message) {
    QString responseTo = message["responseTo"].toString();
    QString status = message["status"].toString();
    if (responseTo == "restoreSession") {
        if ( status == "success") {
            QSettings settings;
            settings.setValue("accessToken", message["accessToken"].toString());
            emit startMainWindow();
        } else {
            emit startAuth();
            QSettings settings;
            settings.remove("accessToken");
            settings.remove("refreshToken");
        }
    }

    if (responseTo == "register") {
        if (status == "error") {
            emit authMessageReceived(message);
        }
    }

    if (responseTo == "login") {
        if (status == "success") {
            QSettings settings;
            settings.setValue("refreshToken", message["refreshToken"].toString());
            settings.setValue("accessToken", message["accessToken"].toString());
            settings.setValue("username", message["username"].toString());
            emit loginSuccess();
        } else {
            emit authMessageReceived(message);
        }
    }

    if (responseTo == "getGroups") {
        if (status == "success") {
            emit mainMessageReceived(message);   
        } else {
            qDebug() << "Failed to get groups" << message["message"].toString();    
        }
    }
}

void MessageDispatcher::onMessageSended(const QJsonObject& message) {
    m_tlsClient->sendMessage(message);
}
