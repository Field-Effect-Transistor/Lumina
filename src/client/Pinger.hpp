//  Pinger.hpp

#pragma once

#include <QObject>
#include <QTimer>
#include <QProcess>
#include <QString>

class Pinger : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Конструктор для створення об'єкта, що пінгує.
     * @param ip Адреса (IP або домен), яку потрібно пінгувати.
     * @param cooldownSeconds Інтервал між пінгами в секундах.
     * @param parent Батьківський об'єкт (для автоматичного керування пам'яттю).
     */
    explicit Pinger(const QString &ip, int cooldownSeconds = 5, QObject *parent = nullptr);

    /**
     * @brief Запускає процес пінгування.
     */
    void start();

    /**
     * @brief Зупиняє процес пінгування.
     */
    void stop();

signals:
    /**
     * @brief Сигнал, що відправляється після кожної спроби пінгу.
     * @param pingResult 1, якщо хост відповів; 0, якщо ні.
     */
    void pinged(int pingResult);

private slots:
    void executePing();
    void onPingProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    QString m_ip;
    QTimer *m_timer;
};
