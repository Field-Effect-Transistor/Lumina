#include "AboutDialog.hpp"
#include <QPixmap>
#include <QFont>
#include <QPalette>

AboutDialog::AboutDialog(QWidget *parent)
    : QDialog(parent) {
    setupUi();
    setWindowTitle("Про Lumina");
    setFixedSize(400, 320);
}

AboutDialog::~AboutDialog() {}

void AboutDialog::setupUi() {
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(10);
    m_mainLayout->setContentsMargins(20, 20, 20, 20);

    // --- Верхня частина з логотипом та назвою ---
    m_topLayout = new QHBoxLayout();
    m_logoLabel = new QLabel(this);

    QPixmap logoPixmap;
    if (qApp->palette().color(QPalette::Window).lightness() > 128) {
        // Світла тема
        logoPixmap.load(":/images/logo_light");
    } else {
        // Темна тема
        logoPixmap.load(":/images/logo_dark");
    }

    if (logoPixmap.isNull()) {
        m_logoLabel->setText("L"); 
        m_logoLabel->setFixedSize(64, 64);
        m_logoLabel->setStyleSheet("QLabel { border: 1px solid gray; font-size: 40px; }");
        m_logoLabel->setAlignment(Qt::AlignCenter);
    } else {
        m_logoLabel->setPixmap(logoPixmap.scaled(64, 64, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }

    m_titleLabel = new QLabel("Lumina", this);
    QFont titleFont = font();
    titleFont.setPointSize(22);
    titleFont.setBold(true);
    m_titleLabel->setFont(titleFont);

    m_topLayout->addWidget(m_logoLabel);
    m_topLayout->addSpacing(15);
    m_topLayout->addWidget(m_titleLabel);
    m_topLayout->addStretch();
    
    m_mainLayout->addLayout(m_topLayout);
    m_mainLayout->addSpacing(15);

    m_descriptionLabel = new QLabel(this);
    m_descriptionLabel->setText("Програмне забезпечення для спрощення розгортання, управління та підключення до безпечних VPN-мереж на базі OpenVPN.");
    m_descriptionLabel->setWordWrap(true);

    m_mainLayout->addWidget(m_descriptionLabel);
    m_mainLayout->addStretch();

    m_versionLabel = new QLabel("Версія: 0.1.1 (Alpha)", this);
    m_authorLabel = new QLabel("Автор: Field Effect Transistor", this);
    m_copyrightLabel = new QLabel("© 2025. Всі права захищено?", this);

    QFont infoFont = font();
    infoFont.setPointSize(infoFont.pointSize() - 1);
    m_versionLabel->setFont(infoFont);
    m_authorLabel->setFont(infoFont);
    m_copyrightLabel->setFont(infoFont);
    
    m_mainLayout->addWidget(m_versionLabel);
    m_mainLayout->addWidget(m_authorLabel);
    m_mainLayout->addWidget(m_copyrightLabel);
    m_mainLayout->addSpacing(15);

    m_okButton = new QPushButton("OK", this);
    connect(m_okButton, &QPushButton::clicked, this, &AboutDialog::accept);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    buttonLayout->addWidget(m_okButton);
    buttonLayout->addStretch();
    
    m_mainLayout->addLayout(buttonLayout);

    setLayout(m_mainLayout);
}
