//  Pinger.cpp

#include "Pinger.hpp"

#include <QDebug>

Pinger::Pinger(const QString &ip, int cooldownSeconds, QObject *parent)
    : QObject(parent), m_ip(ip)
{
    m_timer = new QTimer(this);
    m_timer->setInterval(cooldownSeconds * 1000); // Переводимо секунди в мілісекунди

    connect(m_timer, &QTimer::timeout, this, &Pinger::executePing);
}

void Pinger::start() {
    if (m_timer->isActive()) {
        return; // Вже запущено
    }
    qDebug() << "Pinger started for" << m_ip << "with cooldown" << m_timer->interval() / 1000 << "sec.";
    
    // Виконуємо перший пінг негайно, не чекаючи першого таймауту
    executePing();
    
    // Запускаємо таймер для наступних перевірок
    m_timer->start();
}

void Pinger::stop() {
    if (!m_timer->isActive()) {
        return; // Вже зупинено
    }
    qDebug() << "Pinger stopped for" << m_ip;
    m_timer->stop();
}

void Pinger::executePing() {
    // QProcess буде автоматично видалено, оскільки ми вказуємо this як батьківський об'єкт.
    // Це запобігає витоку пам'яті, якщо Pinger буде знищено до завершення процесу.
    QProcess *pingProcess = new QProcess(this);

    // З'єднуємо сигнал завершення процесу зі слотом-обробником
    connect(pingProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &Pinger::onPingProcessFinished);

    QString command;
    QStringList arguments;

    // Крос-платформені налаштування команди ping
#if defined(Q_OS_WIN)
    command = "ping";
    // -n 1: один запит
    // -w 3000: таймаут 3 секунди на відповідь
    arguments << "-n" << "1" << "-w" << "3000" << m_ip;
#elif defined(Q_OS_LINUX)
    command = "ping";
    // -c 1: один запит
    // -W 3: таймаут 3 секунди
    arguments << "-c" << "1" << "-W" << "3" << m_ip;
#elif defined(Q_OS_MACOS)
    command = "ping";
    // -c 1: один запит
    // -t 3: таймаут 3 секунди
    arguments << "-c" << "1" << "-t" << "3" << m_ip;
#else
    qWarning() << "Pinger is not supported on this OS.";
    // Якщо ОС не підтримується, відправляємо сигнал про невдачу
    // і зупиняємо таймер, щоб не спамити помилками.
    emit pinged(0);
    stop();
    return;
#endif

    qDebug() << "Executing:" << command << arguments.join(" ");
    pingProcess->start(command, arguments);
}

void Pinger::onPingProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    bool success = (exitStatus == QProcess::NormalExit && exitCode == 0);
    
    qDebug() << "Ping result for" << m_ip << "is" << (success ? "Success" : "Failure");
    
    emit pinged(success ? 1 : 0);

    // Важливо: видаляємо процес, який завершив роботу, щоб не накопичувати об'єкти
    sender()->deleteLater();
}
