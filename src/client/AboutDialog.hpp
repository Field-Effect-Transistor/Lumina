//  AboutDialog.hpp

#pragma once

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QApplication>

class AboutDialog : public QDialog {
    Q_OBJECT

public:
    explicit AboutDialog(QWidget *parent = nullptr);
    ~AboutDialog();

private:
    void setupUi();

    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_topLayout;
    
    QLabel *m_logoLabel;
    QLabel *m_titleLabel;
    QLabel *m_descriptionLabel;
    QLabel *m_versionLabel;
    QLabel *m_authorLabel;
    QLabel *m_copyrightLabel;

    QPushButton *m_okButton;
};
