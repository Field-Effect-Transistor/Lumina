//  GroupMemberWidget.hpp

#pragma once

#include <QWidget>
#include <QLabel>
#include <QHBoxLayout>

class Pinger;

class GroupMemberWidget : public QWidget {
    Q_OBJECT
public:
    GroupMemberWidget(
        int id,
        const QString& ip,
        const QString& name,
        QWidget *parent = nullptr
    );
    ~GroupMemberWidget();

private:
    QLabel* m_memberName;
    QLabel* m_memberStatus;

    Pinger* m_pinger;

    int m_id;   
    QString m_ip;

private slots:
    void onPinged(int pingResult);
};
