//  LuminaMainWindow.hpp
#pragma once

#include <QMainWindow>

#include "MessageDispatcher.hpp"

class LuminaMainWindow : public QMainWindow {
    Q_OBJECT
public:
    LuminaMainWindow(MessageDispatcher *dispatcher, QWidget *parent = nullptr);

private:
    MessageDispatcher *m_dispatcher;

private slots:
    void onLogin();

};
