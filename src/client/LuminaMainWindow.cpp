//  LuminaMainWindow.cpp

#include "LuminaMainWindow.hpp"

LuminaMainWindow::LuminaMainWindow(
    MessageDispatcher *dispatcher,
    QWidget *parent
) : QMainWindow(parent),
    m_dispatcher(dispatcher) {

    connect(m_dispatcher, &MessageDispatcher::login, this, &LuminaMainWindow::onLogin);
    connect(m_dispatcher, &MessageDispatcher::startMainWindow, this, &LuminaMainWindow::onLogin);
}

void LuminaMainWindow::onLogin() {
    show();
}