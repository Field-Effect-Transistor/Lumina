//  RestoreDialog.cpp

#include "RestoreDialog.hpp"

RestoreDialog::RestoreDialog(QWidget *parent) : QDialog(parent) {
    layout = new QVBoxLayout(this);

    setWindowTitle("Restore password");
    layout->addStretch(1);
    
    QLineEdit* emailInput = new QLineEdit(this);
    emailInput->setPlaceholderText("Enter email");
    layout->addWidget(emailInput);
    QPushButton* sendButton = new QPushButton("Send", this);
    layout->addWidget(sendButton);
    layout->addStretch(1);
    setFixedSize(300, 100);
}

void RestoreDialog::onSendButtonClicked() {

    
}
