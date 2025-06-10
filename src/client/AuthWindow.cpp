//  AuthWindow.cpp

#include "AuthWindow.hpp"

AuthWindow::AuthWindow(QWidget *parent) : QWidget(parent) {
    setWindowTitle("Lumina - Sing in");
    QPixmap logoPixmap;
    if ( QApplication::palette().color(QPalette::Window).lightness() > 128 ) {
        setWindowIcon(QIcon(":/icons/icon_light"));
        logoPixmap.load(":/images/logo_light");
    } else {
        setWindowIcon(QIcon(":/icons/icon_dark"));
        logoPixmap.load(":/images/logo_dark");
    }

    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(15, 15, 15, 15);

    mainLayout->addStretch(1);

    logo = new QLabel(this);
    if (logoPixmap.isNull()) {
        logo->setText("Logo not found");
    }
    logo->setPixmap(logoPixmap);
    logo->setScaledContents(true);
    logo->setFixedSize(300, 100);
    // logo->setFixedHeight(100);
    mainLayout->addWidget(logo, 0, Qt::AlignCenter | Qt::AlignTop);

    mainLayout->addStretch(1);

    inputBox = new QGroupBox(this);
    inputLayout = new QVBoxLayout(inputBox);
    usernameInput = new QLineEdit(this);
    usernameInput->setPlaceholderText("Username");
    passwordInput = new QLineEdit(this);
    passwordInput->setPlaceholderText("Password");
    passwordInput->setEchoMode(QLineEdit::Password);
    loginButton = new QPushButton("Sing in", this);
    registerButton = new QPushButton("Create account", this);
    inputLayout->addWidget(usernameInput);
    inputLayout->addWidget(passwordInput);
    inputLayout->addWidget(loginButton);
    mainLayout->addWidget(inputBox, 0, Qt::AlignTop);

    mainLayout->addStretch(1);

    mainLayout->addWidget(registerButton);
    setFixedHeight(500);
    setFixedWidth(330);
    
}
