//  LuminaMainWindow.hpp
#pragma once

#include <vector>

#include <QMainWindow>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>
#include <QTimer>

#include "MessageDispatcher.hpp"

class GroupWidget;

class LuminaMainWindow : public QMainWindow {
    Q_OBJECT
public:
    LuminaMainWindow(MessageDispatcher *dispatcher, QWidget *parent = nullptr);

private:
    QWidget* m_centralWidget;
    QVBoxLayout* m_central_layout;

    QPushButton* m_connectButton;
    
    QScrollArea* m_scrollArea;
    QWidget* m_scrollAreaContent;
    std::vector<GroupWidget*> m_groups;

    QPushButton* m_logoutButton;

    QProcess* m_process;
    QTimer* m_vpnStatusTimer;
    int m_ipCheckAttempts = 0;

    MessageDispatcher *m_dispatcher;

signals:
    void sendMessage(const QJsonObject& message);
    void disconnectVpn();

private slots:
    void onLoginSuccess();
    void onLogoutButtonClicked();
    void onMessageReceived(const QJsonObject& message);
    void updateGroups(const QJsonArray& groups);
    void onDisconnected();

    void onVpnConnected();
    void onVpnDisconnect();
    void checkVpnIpAddress();

    void onConnectButtonClicked();
    
protected:
    void closeEvent(QCloseEvent *event) override;

};
