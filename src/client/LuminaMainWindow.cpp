//  LuminaMainWindow.cpp

#include "LuminaMainWindow.hpp"

#include "GroupWidget.hpp"

#include <QStatusBar>
#include <QWidget>
#include <QSettings>
#include <QApplication>
#include <QSettings>
#include <QMessageBox>

#include <fstream>

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

    m_process = new QProcess(this);
    m_process->setProcessChannelMode(QProcess::MergedChannels);

    connect(m_process, &QProcess::started, this, &LuminaMainWindow::onVpnConnected);
    connect(m_process, &QProcess::finished, this, [this](int, QProcess::ExitStatus){ onVpnDisconnect(); });
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError){ 
        onVpnDisconnect(); 
        QMessageBox::critical(this, "Error", "VPN connection error");
    });
    connect(m_process, &QProcess::readyRead, this, [this]() {
        while(m_process->canReadLine()) {
            QByteArray lineBytes = m_process->readLine();
            QString line = QString::fromLocal8Bit(lineBytes).trimmed();
            qDebug() << line;
        }
    });

    connect(m_dispatcher, &MessageDispatcher::loginSuccess, this, &LuminaMainWindow::onLoginSuccess);
    //connect(m_dispatcher, &MessageDispatcher::startMainWindow, this, &LuminaMainWindow::onLoginSuccess);
    connect(this, &LuminaMainWindow::sendMessage, m_dispatcher, &MessageDispatcher::onMessageSended);
    connect(m_logoutButton, &QPushButton::clicked, this, &LuminaMainWindow::onLogoutButtonClicked);
    connect(m_dispatcher, &MessageDispatcher::mainMessageReceived, this, &LuminaMainWindow::onMessageReceived);
    connect(m_dispatcher, &MessageDispatcher::disconnected, this, &LuminaMainWindow::onDisconnected);
    connect(m_connectButton, &QPushButton::clicked, this, &LuminaMainWindow::onConnectButtonClicked);
}

void LuminaMainWindow::onLoginSuccess() {
    //  get groups
    QSettings settings;
    QString accessToken =  settings.value("accessToken").toString();

    QJsonObject request;
    request["command"] = "getGroups";
    QJsonObject params;
    params["accessToken"] = accessToken;
    request["params"] = params;
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
    if (message["responseTo"].toString() == "getGroups") {
        updateGroups(message["groups"].toArray());
    } else if (message["responseTo"].toString() == "ovpn") {
        if (message["status"].toString() == "error") {
            QMessageBox::warning(this, "Error", message["message"].toString()); 
        } else {
            std::ofstream file("/tmp/lumina.ovpn");
            file << message["ovpn"].toString().toStdString();
            file.close();

            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            env.insert("SUDO_ASKPASS", "/usr/bin/ksshaskpass");
            m_process->setProcessEnvironment(env);

            QString program = "sudo";
            QStringList arguments;
            arguments << "-A" << "openvpn" << "/tmp/lumina.ovpn";
            
            m_process->start(program, arguments);
        }
    }
}

void LuminaMainWindow::onDisconnected() {
    hide();
}

void LuminaMainWindow::onConnectButtonClicked() {
    if (m_connectButton->text() == "Connect") {
        QSettings settings;
        QString accessToken =  settings.value("accessToken").toString();
    
        QJsonObject request;
        request["command"] = "ovpn";
        QJsonObject params;
        params["accessToken"] = accessToken;
        request["params"] = params;
        emit sendMessage(request);
    } else {
        onVpnDisconnect();
    }
}

void LuminaMainWindow::onVpnDisconnect() {
    m_connectButton->setText("Connect");
    if (m_process->state() == QProcess::Running) {
        m_process->kill();
    }
}

void LuminaMainWindow::onVpnConnected() {
    m_connectButton->setText("Disconnect");
}