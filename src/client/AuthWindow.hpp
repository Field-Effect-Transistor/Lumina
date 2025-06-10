//  AuthWindow.hpp

#pragma once

#include <QWidget>
//#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QStackedWidget>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QGroupBox>

class AuthWindow : public QWidget {
    Q_OBJECT
public:
    explicit AuthWindow(QWidget *parent = nullptr);
    ~AuthWindow() {};

private:
    QVBoxLayout* mainLayout;
    //QPushButton*    menu;
    QLabel* logo;
    QGroupBox*  inputBox;
    QVBoxLayout* inputLayout;

    QLineEdit*  usernameInput;
    QLineEdit*  passwordInput;
    QPushButton* loginButton;
    
    QPushButton* registerButton;

};
