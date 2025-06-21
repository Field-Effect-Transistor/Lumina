//  MessageDispatcher.cpp

#include "MessageDispatcher.hpp"
#include "LuminaTlsClient.hpp"

#include <QSettings>
#include <QMessageBox>
#include <QPointer>
#include <QApplication>

MessageDispatcher::MessageDispatcher(LuminaTlsClient *client, QObject *parent)
    : QObject(parent),
    m_tlsClient(client) {
    connect(m_tlsClient, &LuminaTlsClient::messageReceived, this, &MessageDispatcher::onMessageReceived);
    connect(m_tlsClient, &LuminaTlsClient::connected, this, &MessageDispatcher::onConnected);
    connect(m_tlsClient, &LuminaTlsClient::disconnected, this, &MessageDispatcher::onDisconnected);
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
        //m_tlsClient->sendMessage(request);
        onMessageSended(request);
    }
}

void MessageDispatcher::onMessageReceived(const QJsonObject& message) {
    QString responseTo = message["responseTo"].toString();
    QString status = message["status"].toString();
    if (responseTo == "restoreSession") {
        if ( status == "success") {
            QSettings settings;
            settings.setValue("accessToken", message["accessToken"].toString());
            emit loginSuccess();
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
            qDebug() << "[Dispatcher] Failed to get groups" << message["message"].toString();    
        }
    } else if (
        responseTo == "ovpn" ||
        responseTo == "createGroup"
    ) {
        emit mainMessageReceived(message);
    }

    if (responseTo == "any") {
        if (status == "updateAccessToken") {
            m_lastRequest = message["request"].toObject();

            QSettings settings;
            QString refreshToken = settings.value("refreshToken").toString();
            QJsonObject request;
            request["command"] = "restoreSession";
            QJsonObject params;
            params["refreshToken"] = refreshToken;
            request["params"] = params;
            //m_tlsClient->sendMessage(request);
            onMessageSended(request);
        }
    }

    if (m_lastRequest.has_value()) {
        m_lastRequest.value()["accessToken"] = message["accessToken"].toString();
        //m_tlsClient->sendMessage(m_lastRequest.value());
        onMessageSended(m_lastRequest.value());
        m_lastRequest = std::nullopt;
    }
}

void MessageDispatcher::onMessageSended(const QJsonObject& message) {
    qDebug() << "Message sent:" << message;
    m_tlsClient->sendMessage(message);
}

void MessageDispatcher::onDisconnected() {
    emit disconnected();

    QPointer<QMessageBox> msgBox = new QMessageBox();
    msgBox->setAttribute(Qt::WA_DeleteOnClose);
    msgBox->setIcon(QMessageBox::Warning);
    msgBox->setWindowTitle(tr("З'єднання втрачено"));
    msgBox->setText(tr("Було втрачено з'єднання з сервером."));
    msgBox->setInformativeText(tr("Спробувати перепідключитися?"));
    
    msgBox->setStandardButtons(QMessageBox::Retry | QMessageBox::Close);
    msgBox->setDefaultButton(QMessageBox::Retry);

    connect(msgBox, &QMessageBox::finished, this, [this](int result) {
        if (result == QMessageBox::Retry) {
            m_tlsClient->reconnectToServer();
        } else {
            QApplication::quit();
        }
    });

    msgBox->open(); 
}
