//  GroupMemberWidget.cpp

#include "GroupMemberWidget.hpp"

#include "Pinger.hpp"

GroupMemberWidget::GroupMemberWidget(
    int id,
    const QString& ip,
    const QString& name,
    QWidget *parent
) : QWidget(parent),
    m_id(id),
    m_ip(ip) {

    m_memberName = new QLabel(name, this);
    m_memberStatus = new QLabel("Offline" ,this);

    QHBoxLayout* layout = new QHBoxLayout(this);
    layout->addWidget(m_memberName, Qt::AlignLeft);
    layout->addWidget(m_memberStatus, Qt::AlignRight);
    
    m_pinger = new Pinger(ip, 5, this);
    connect(m_pinger, &Pinger::pinged, this, &GroupMemberWidget::onPinged);

    setLayout(layout);
}

void GroupMemberWidget::onPinged(int pingResult) {
    if (pingResult == 1) {
        m_memberStatus->setText("Online");
    } else {
        m_memberStatus->setText("Offline");
    }
}
