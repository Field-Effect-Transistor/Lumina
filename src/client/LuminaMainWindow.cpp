//  LuminaMainWindow.cpp

#include "LuminaMainWindow.hpp"

#include "GroupWidget.hpp"

#include <QStatusBar>
#include <QWidget>
#include <QSettings>
#include <QApplication>
#include <QSettings>

LuminaMainWindow::LuminaMainWindow(
    MessageDispatcher *dispatcher,
    QWidget *parent
) : QMainWindow(parent),
    m_dispatcher(dispatcher) {

    setWindowTitle("Lumina Client");

    //layout()->setContentsMargins(15, 15, 15, 15);

    m_centralWidget = new QWidget(this);
    setCentralWidget(m_centralWidget);

    m_central_layout = new QVBoxLayout(m_centralWidget);
    
    m_connectButton = new QPushButton("Connect", this);
    m_scrollArea = new QScrollArea(this);
    m_logoutButton = new QPushButton("Logout", this);
    m_scrollAreaContent = new QWidget(m_scrollArea);
    m_scrollArea->setWidget(m_scrollAreaContent);

    m_central_layout->addWidget(m_connectButton);
    m_central_layout->addWidget(m_scrollArea);
    m_central_layout->addWidget(m_logoutButton);

    statusBar()->showMessage("Ready");

    resize(330, 500);
    setMaximumHeight(600);
    setMinimumHeight(300);
    setFixedWidth(330);   

    connect(m_dispatcher, &MessageDispatcher::loginSuccess, this, &LuminaMainWindow::onLoginSuccess);
    //connect(m_dispatcher, &MessageDispatcher::startMainWindow, this, &LuminaMainWindow::onLoginSuccess);
    connect(this, &LuminaMainWindow::sendMessage, m_dispatcher, &MessageDispatcher::onMessageSended);
    connect(m_logoutButton, &QPushButton::clicked, this, &LuminaMainWindow::onLogoutButtonClicked);
    connect(m_dispatcher, &MessageDispatcher::mainMessageReceived, this, &LuminaMainWindow::onMessageReceived);
}

void LuminaMainWindow::onLoginSuccess() {
    //  get groups
    QSettings settings;
    QString accessToken =  settings.value("accessToken").toString();
    QJsonObject request;
    request["command"] = "getGroups";
    request["accessToken"] = accessToken;
    emit sendMessage(request);

    show();
}

void LuminaMainWindow::onLogoutButtonClicked() {
    QSettings settings;
    settings.remove("username");
    settings.remove("accessToken");
    settings.remove("refreshToken");
    hide();
    emit m_dispatcher->startAuth();
}

void LuminaMainWindow::closeEvent(QCloseEvent *event) {
    QApplication::quit();
}

void LuminaMainWindow::updateGroups(const QJsonArray& groups) {
    //  clear groups
    for (GroupWidget* group : m_groups) {
        m_central_layout->removeWidget(group);
        delete group;
    }
    m_groups.clear();

    //  add groups
    for (const auto& group_val : groups) {
        m_groups.push_back(new GroupWidget(
            group_val.toObject()["id"].toInt(),
            group_val.toObject()["name"].toString(),
            group_val.toObject()["members"].toArray(),
            this
        ));
        m_central_layout->addWidget(m_groups.back());
    }
}

void LuminaMainWindow::onMessageReceived(const QJsonObject& message) {
    if (message["command"].toString() == "getGroups") {
        updateGroups(message["groups"].toArray());
    }
}
