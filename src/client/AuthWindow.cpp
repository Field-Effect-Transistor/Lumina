//  AuthWindow.cpp

#include "AuthWindow.hpp"

AuthWindow::AuthWindow(QWidget *parent) : QWidget(parent) {
    setWindowTitle("Lumina - Auth");
    // Закоментуйте або видаліть setFixedHeight, щоб дозволити зміну висоти
    // setFixedHeight(350);
    // setFixedWidth(300); // Також краще прибрати, якщо потрібна повна динамічність

    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20); // Додамо відступи для кращого вигляду

    logo = new QLabel(this);
    QPixmap originalPixmap(":/images/logo"); // Завантажуємо оригінал один раз
    if (originalPixmap.isNull()) {
        logo->setText("Logo not found!"); // Обробка помилки
    } else {
        logo->setPixmap(originalPixmap);
    }
    logo->setAlignment(Qt::AlignCenter); // Вирівнюємо лого по центру

    // === Ключовий момент для динамічного розміру ===
    logo->setScaledContents(true);
    // === === === === === === === === === === === ===

    // Встановлюємо мінімальний розмір для лого, щоб воно не зникало зовсім
    logo->setMinimumSize(50, 50); // Наприклад, 50x50 пікселів

    // (Опціонально) Встановлюємо політику розміру для QLabel, щоб він міг розширюватися
    //QSizePolicy logoSizePolicy = logo->sizePolicy();
    //logoSizePolicy.setVerticalPolicy(QSizePolicy::Expanding); // Може розширюватися вертикально
    //logoSizePolicy.setHorizontalPolicy(QSizePolicy::Expanding); // Може розширюватися горизонтально
    //logo->setSizePolicy(logoSizePolicy);
    // Часто це не потрібно, якщо layout дозволяє розтягування

    mainLayout->addWidget(logo, 1); // Додаємо лого з коефіцієнтом розтягування 1

    inputBox = new QGroupBox(this); // Не передаємо parent, бо він додається в layout
    inputLayout = new QVBoxLayout(); // Не передаємо parent, бо він встановлюється для groupBox
    inputBox->setLayout(inputLayout);
    mainLayout->addWidget(inputBox, 0); // inputbox не буде розтягуватися, якщо лого розтягується

    usernameInput = new QLineEdit(); // Не передаємо parent
    usernameInput->setPlaceholderText("Username");
    inputLayout->addWidget(usernameInput);

    passwordInput = new QLineEdit(); // Не передаємо parent
    passwordInput->setPlaceholderText("Password");
    passwordInput->setEchoMode(QLineEdit::Password);
    inputLayout->addWidget(passwordInput);

    loginButton = new QPushButton("Sign In"); // Не передаємо parent
    inputLayout->addWidget(loginButton);

    registerButton = new QPushButton("Sign Up", this); // 'this' як parent, бо додається напряму в mainLayout
    mainLayout->addWidget(registerButton, 0); // registerButton не буде розтягуватися

    setLayout(mainLayout); // Встановлюємо головний layout для вікна AuthWindow

    // Встановлюємо початковий розмір вікна, який може змінюватися користувачем
    resize(300, 450); // Наприклад
    // Встановлюємо мінімальний розмір вікна, щоб інтерфейс не "зламувався"
    setMinimumSize(250, 350);
}

