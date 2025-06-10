//  RestoreDialog.hpp

#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

class RestoreDialog : public QDialog {
    Q_OBJECT
public:
    RestoreDialog(QWidget *parent = nullptr);
    ~RestoreDialog() {}

private:
    QVBoxLayout* layout;
    QLineEdit* emailInput;
    QPushButton* sendButton;

private slots:
    void onSendButtonClicked();
};

