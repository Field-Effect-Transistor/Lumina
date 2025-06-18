//  AuthWindow.cpp

#include "AuthWindow.hpp"
#include "LuminaTlsClient.hpp"
#include "ValidationUtils.hpp"
#include "MessageDispatcher.hpp"

#include <QJsonObject>
#include <QDebug>
#include <QMessageBox>

AuthWindow::AuthWindow(
    LuminaTlsClient* client,
    MessageDispatcher* dispatcher,
    QWidget *parent
)
    : QWidget(parent),
    m_tlsClient(client),
    m_dispatcher(dispatcher)
{
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

    //  Valiadation
    connect(loginUsernameInput, &QLineEdit::editingFinished, this, [&](){
        AuthWindow::validateEmail(loginUsernameInput);
    });
    connect(regUsernameInput, &QLineEdit::editingFinished, this, [&](){
        AuthWindow::validateEmail(regUsernameInput);
    });
    connect(regPasswordInput, &QLineEdit::editingFinished, this, [&](){
        AuthWindow::validatePass(regPasswordInput);
    });
    connect(regPasswordConfirmInput, &QLineEdit::editingFinished, this, [&](){
        AuthWindow::validatePassConfirm(regPasswordInput, regPasswordConfirmInput);
    });

    //  Show on connection to server
    connect(m_tlsClient, &LuminaTlsClient::connected, this, [&](){
        this->show();
    });

    //  Hide on disconnection
    connect(m_tlsClient, &LuminaTlsClient::disconnected, this, &AuthWindow::onDisconnected);

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
    auto res =  ValidationUtils::validateEmail(email);    
    if (res.has_value()){
        QMessageBox::warning(this, "Error: Invalid email", res->message.c_str());
        return;
    }

    res = ValidationUtils::validatePassword(pass);
    if (res.has_value()) {
        QMessageBox::warning(this, "Error: Invalid password", res->message.c_str());
        return;
    }

    if (pass != conpass) {
        QMessageBox::warning(this, "Error: Passwords don't match", "Passwords don't match");
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
    onChangePageButtonClicked();
}

void AuthWindow::validatePass(QLineEdit* passLine) {
    auto res = ValidationUtils::validatePassword(
        passLine->text().toStdString()
    );
    if (res.has_value()) {
        passLine->setStyleSheet("QLineEdit { color: red; }");
        qDebug() << res->field.c_str() << res->message.c_str();
    } else {
        passLine->setStyleSheet("QLineEdit { color: green; }");
    } 
}

void AuthWindow::validatePassConfirm(const QLineEdit* passLine, QLineEdit* passConfLine) {
    if (passLine->text() != passConfLine->text()) {
        passConfLine->setStyleSheet("QLineEdit { color: red; }");
        qDebug() << "Passwords don't match";
    } else {
        passConfLine->setStyleSheet("QLineEdit { color: green; }");
    }
}

void AuthWindow::validateEmail(QLineEdit* emailLine) {
    auto res = ValidationUtils::validateEmail(
        emailLine->text().toStdString()
    ); 
    if (res.has_value()) {
        emailLine->setStyleSheet("QLineEdit { color: red; }");
        qDebug() << res->field.c_str() << res->message.c_str();
    } else {
        emailLine->setStyleSheet("QLineEdit { color: green; }");
    }
}

void AuthWindow::onDisconnected() {
    this->hide();

    QMessageBox msgBox(this);
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setWindowTitle(tr("З'єднання втрачено"));
    msgBox.setText(tr("Було втрачено з'єднання з сервером."));
    msgBox.setInformativeText(tr("Спробувати перепідключитися?"));
    
    msgBox.setStandardButtons(QMessageBox::Retry | QMessageBox::Close);
    msgBox.setDefaultButton(QMessageBox::Retry);

    int choice = msgBox.exec();

    if (choice == QMessageBox::Retry) {
        m_tlsClient->reconnectToServer();
    } else {
        this->close();
    }
}
