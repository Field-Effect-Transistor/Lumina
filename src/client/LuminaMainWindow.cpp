//  LuminaMainWindow.cpp

#include "LuminaMainWindow.hpp"

#include "GroupWidget.hpp"

#include <QStatusBar>
#include <QWidget>
#include <QSettings>
#include <QApplication>
#include <QSettings>
#include <QMessageBox>

#include <QNetworkInterface>
#include <QHostAddress>

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

    statusBar()->showMessage("Ready to connect");

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
            qDebug() << "[VPN client] " << line;
        }
    });

    m_vpnStatusTimer = new QTimer(this);
    connect(m_vpnStatusTimer, &QTimer::timeout, this, &LuminaMainWindow::checkVpnIpAddress);

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
    onVpnDisconnect();
    emit m_dispatcher->startAuth();
}

void LuminaMainWindow::closeEvent(QCloseEvent *event) {
    qDebug() << "LuminaMainWindow::closeEvent triggered.";
    onVpnDisconnect();
    QMainWindow::closeEvent(event);
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
    onVpnDisconnect();
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
    m_connectButton->setText(tr("Connect"));
    statusBar()->showMessage(tr("VPN: Disconnected"));

    if (m_vpnStatusTimer && m_vpnStatusTimer->isActive()) {
        m_vpnStatusTimer->stop();
        qDebug() << "VPN status timer stopped.";
    }
    m_ipCheckAttempts = 0;

    if (m_process && m_process->state() != QProcess::NotRunning) {
        qDebug() << "VPN process is running. Attempting to stop it.";
        
        m_process->terminate();
        
        if (!m_process->waitForFinished(1000)) {
            qWarning() << "VPN process did not terminate gracefully after 3s. Killing...";
            m_process->kill();
            
            
            if (!m_process->waitForFinished(1000)) {
                qWarning() << "VPN process did not stop even after kill within 1s. It might still be running orphaned.";
            } else {
                qDebug() << "VPN process killed and finished.";
            }
        } else {
            qDebug() << "VPN process terminated gracefully and finished.";
        }
    } else {
        qDebug() << "VPN process was not running or m_process is null.";
    }
}

void LuminaMainWindow::onVpnConnected() {
    m_connectButton->setText(tr("Disconnect")); // Використовуйте tr()
    statusBar()->showMessage(tr("VPN: Connecting..."));
    m_ipCheckAttempts = 0; // Скидаємо лічильник перед стартом
    m_vpnStatusTimer->start(2000); // Запускаємо таймер, перевірка кожні 2 секунди (2000 мс)
    qDebug() << "VPN process started, status timer initiated.";
}

// Новий слот, який викликається таймером
void LuminaMainWindow::checkVpnIpAddress() {
    m_ipCheckAttempts++;
    qDebug() << "Checking for tun0 IP (Attempt:" << m_ipCheckAttempts << ")";

    QString targetInterfaceName = "tun0";
    QHostAddress tun0_ip;
    QNetworkInterface interface = QNetworkInterface::interfaceFromName(targetInterfaceName);

    if (interface.isValid() && interface.flags().testFlag(QNetworkInterface::IsUp)) {
        QList<QNetworkAddressEntry> entries = interface.addressEntries();
        foreach (const QNetworkAddressEntry &entry, entries) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol) {
                tun0_ip = entry.ip();
                break;
            }
        }

        if (!tun0_ip.isNull()) {
            statusBar()->showMessage(tr("VPN: Connected | ") + tun0_ip.toString());
            m_vpnStatusTimer->stop();
            qDebug() << "tun0 IP found:" << tun0_ip.toString() << ". Timer stopped.";
        } else {
            statusBar()->showMessage(tr("VPN: Acquiring IP... (Attempt: %1)").arg(m_ipCheckAttempts));
            qDebug() << "tun0 is UP, but no IPv4 address yet.";
        }
    } else {
        if (!interface.isValid()) {
            statusBar()->showMessage(tr("VPN: Interface tun0 not found (Attempt: %1)").arg(m_ipCheckAttempts));
            qDebug() << "tun0 interface not found.";
        } else {
            statusBar()->showMessage(tr("VPN: Interface tun0 is down (Attempt: %1)").arg(m_ipCheckAttempts));
            qDebug() << "tun0 interface is down.";
        }
    }

    if (m_ipCheckAttempts >= 15 && m_vpnStatusTimer->isActive()) {
        qWarning() << "Failed to get tun0 IP after" << m_ipCheckAttempts << "attempts. Stopping timer.";
        statusBar()->showMessage(tr("VPN: Failed to acquire IP for tun0"));
        m_vpnStatusTimer->stop();
    }
}
