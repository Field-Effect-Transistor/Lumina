//  GroupWidget.cpp

#include "GroupWidget.hpp"

#include "GroupMemberWidget.hpp"

GroupWidget::GroupWidget(
    int id,
    const QString& name,
    const QJsonArray& members,
    QWidget *parent
) : QWidget(parent),
    m_id (id) {

    m_groupBox = new QGroupBox(name, this);
    m_layout = new QVBoxLayout(m_groupBox);

    for (const auto& member_val : members) { 
        m_members.push_back(new GroupMemberWidget(
            member_val.toObject()["id"].toInt(),
            member_val.toObject()["ip"].toString(),
            member_val.toObject()["name"].toString(),
            this
        ));
        m_layout->addWidget(m_members.back());
    }

}
