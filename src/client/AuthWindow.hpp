//  AuthWindow.hpp

#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QGroupBox>
#include <QIcon>
#include <QApplication>
#include <QPalette>
#include <QColor>
#include <QStackedWidget>
#include <QDialog>

#include "RestoreDialog.hpp"

class LuminaTlsClient;
class MessageDispatcher;

class AuthWindow : public QWidget {
    Q_OBJECT
public:
    explicit AuthWindow(
        LuminaTlsClient* client,
        MessageDispatcher* dispatcher,
        QWidget *parent = nullptr
    );
    ~AuthWindow() {};

private:
    QVBoxLayout* mainLayout;
    //QPushButton*    menu;
    QLabel* logo;

    QStackedWidget* authWidget;

    QGroupBox*  loginBox;
    QVBoxLayout* loginLayout;
    QLineEdit*  loginUsernameInput;
    QLineEdit*  loginPasswordInput;
    QPushButton* loginButton;
    QPushButton* restoreLink;

    QGroupBox*  regBox;
    QVBoxLayout* regLayout;
    QLineEdit*  regUsernameInput;
    QLineEdit*  regPasswordInput;
    QLineEdit*  regPasswordConfirmInput;
    QPushButton* regButton;

    QPushButton* changePageButton;

    LuminaTlsClient* m_tlsClient;
    MessageDispatcher* m_dispatcher;

private slots:
    void onChangePageButtonClicked();
    void onRestoreLinkClicked();
    void onLoginButtonClicked();
    void onRegButtonClicked();
    void onDisconnected();

    void onLogin();

    void validatePass(QLineEdit* passLine);
    void validatePassConfirm(const QLineEdit* passLine, QLineEdit* passConfLine);
    void validateEmail(QLineEdit* emailLine);

};
