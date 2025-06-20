//  GroupWidget.hpp

#pragma once

#include <QWidget>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>

class GroupMemberWidget;

class GroupWidget : public QWidget {
public:
    GroupWidget(
        int id,
        const QString& name,
        const QJsonArray& members,
        QWidget *parent = nullptr
    );
    ~GroupWidget() {}


private:
    QGroupBox* m_groupBox;
    QVBoxLayout* m_layout;

    int m_id;

    std::vector<GroupMemberWidget*> m_members;

};
