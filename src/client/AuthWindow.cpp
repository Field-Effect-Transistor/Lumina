//  AuthWindow.cpp

#include "AuthWindow.hpp"
#include "LuminaTlsClient.hpp"
#include "ValidationUtils.hpp"

#include <QJsonObject>

AuthWindow::AuthWindow(QWidget *parent, LuminaTlsClient* client) : QWidget(parent), m_tlsClient(client) {
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

    authWidget = new QStackedWidget(this);

    // login box
    loginBox = new QGroupBox(authWidget);
    loginLayout = new QVBoxLayout(loginBox);
    loginUsernameInput = new QLineEdit(loginBox);
    loginUsernameInput->setPlaceholderText("Username");
    loginPasswordInput = new QLineEdit(loginBox);
    loginPasswordInput->setPlaceholderText("Password");
    loginPasswordInput->setEchoMode(QLineEdit::Password);
    loginButton = new QPushButton("Sing in", loginBox);
    changePageButton = new QPushButton("Create account", loginBox);
    restoreLink = new QPushButton(loginBox);
    restoreLink->setStyleSheet(
        "QPushButton {"
        "    border: none; /* Прибрати рамку кнопки */"
        "    background-color: transparent; /* Прозорий фон */"
        "    color: #00aaff; /* Колір тексту як у посилання */"
        "    text-decoration: underline; /* Підкреслення */"
        "    padding: 0; /* Прибрати внутрішні відступи, якщо є */"
        "    text-align: left; /* Вирівнювання тексту, якщо потрібно */"
        "}"
        "QPushButton:hover {"
        "    color: blue; /* Зміна кольору при наведенні */"
        "}"
        "QPushButton:pressed {"
        "    color: blue; /* Зміна кольору при натисканні */"
        "}"
    );
    restoreLink->setText("Restore password");
    loginLayout->addWidget(changePageButton);
    loginLayout->addWidget(restoreLink);
    loginLayout->addWidget(loginUsernameInput);
    loginLayout->addWidget(loginPasswordInput);
    loginLayout->addWidget(loginButton);
    loginLayout->addWidget(restoreLink);
    //mainLayout->addWidget(loginBox, 0, Qt::AlignTop);

    //register box
    regBox = new QGroupBox(this);
    regLayout = new QVBoxLayout(regBox);
    regUsernameInput = new QLineEdit(regBox);
    regUsernameInput->setPlaceholderText("Username");
    regPasswordInput = new QLineEdit(regBox);
    regPasswordInput->setPlaceholderText("Password");
    regPasswordInput->setEchoMode(QLineEdit::Password);
    regPasswordConfirmInput = new QLineEdit(regBox);
    regPasswordConfirmInput->setPlaceholderText("Confirm Password");
    regPasswordConfirmInput->setEchoMode(QLineEdit::Password);
    regButton = new QPushButton("Sing up", regBox);
    regLayout->addWidget(regUsernameInput);
    regLayout->addWidget(regPasswordInput);
    regLayout->addWidget(regPasswordConfirmInput);
    regLayout->addWidget(regButton);
    //mainLayout->addWidget(regBox, 0, Qt::AlignTop);


    authWidget->addWidget(loginBox);
    authWidget->addWidget(regBox);

    mainLayout->addWidget(authWidget);
    mainLayout->addStretch(1);

    mainLayout->addWidget(changePageButton);
    setFixedHeight(500);
    setFixedWidth(330);    

    connect(changePageButton, &QPushButton::clicked, this, &AuthWindow::onChangePageButtonClicked);
    connect(restoreLink, &QPushButton::clicked, this, &AuthWindow::onRestoreLinkClicked);
    connect(loginButton, &QPushButton::clicked, this, &AuthWindow::onLoginButtonClicked);
    connect(regButton, &QPushButton::clicked, this, &AuthWindow::onRegButtonClicked);

    //  Valia
}

void AuthWindow::onChangePageButtonClicked() {
    if (authWidget->currentIndex() == 0) {
        authWidget->setCurrentIndex(1);
        setWindowTitle("Lumina - Sing up");
        changePageButton->setText("Login");
    } else {
        authWidget->setCurrentIndex(0);
        setWindowTitle("Lumina - Sing in");
        changePageButton->setText("Create account");
    }
}

void AuthWindow::onRestoreLinkClicked() {
    RestoreDialog(this).exec();
}

void AuthWindow::onLoginButtonClicked() {

}

void AuthWindow::onRegButtonClicked() {
    const std::string& email =regUsernameInput->text().toStdString();
    const std::string& pass = regPasswordInput->text().toStdString();
    const std::string& conpass = regPasswordConfirmInput->text().toStdString();

    //  Validation  
    //! may be removed to seprate slot on change line signal
    auto res =  ValidationUtils::validateEmail(email);    
    if (res.has_value()){
        //  turn editline red
        //  throw QDialog
        return;
    }

    res = ValidationUtils::validatePassword(pass);
    if (res.has_value()) {
        //  turn line red
        return;
    }

    if (pass != conpass) {
        //  turn line red
        //  trow QDialog
        return;
    }

    //  sending Request
    QJsonObject request;
    request["command"] = "register";

    QJsonObject params;
    params["username"] = regUsernameInput->text();
    params["password"] = regPasswordInput->text();
    request["params"] = params;

    m_tlsClient->sendMessage(request);
}

void AuthWindow::validatePass(const QLineEdit* passLine) {
    if (ValidationUtils::validatePassword(
        passLine->text().toStdString()
    ).has_value()) {
        //! make it red;
    } else {
        //! return own color
    }
}

void AuthWindow::validatePassConfirm(const QLineEdit* passLine, const QLineEdit* passConfLine) {
    if (passLine->text() != passConfLine->text()) {
        //! make it red
    } else {
        //! return original color
    }
}

void AuthWindow::validateEmail(const QLineEdit* emailLine) {
    if (ValidationUtils::validateEmail(
        emailLine->text().toStdString()
    ).has_value()) {
        //! turn it red
    } else {
        //! return own color
    }
}
