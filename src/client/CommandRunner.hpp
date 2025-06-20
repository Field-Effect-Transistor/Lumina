//  CommandRunner.hpp

#pragma once

#include <QObject>
#include <QStringList>
#include <QProcess>
#include <QThread>

class CommandRunner : public QObject {
    Q_OBJECT

public:
    explicit CommandRunner(QObject *parent = nullptr);
    ~CommandRunner();

    /**
     * @brief Запускає виконання команди в окремому потоці.
     * @param program Шлях до виконуваного файлу.
     * @param arguments Список аргументів для команди.
     */
    void startCommand(const QString &program, const QStringList &arguments);

    /**
     * @brief Завершує виконання команди.
     */
    void stopCommand();

signals:
    /**
     * @brief Сигнал, що випромінюється, коли з'являється новий вивід (stdout).
     */
    void outputReceived(const QString &output);

    /**
     * @brief Сигнал, що випромінюється, коли з'являється новий вивід помилок (stderr).
     */
    void errorOutputReceived(const QString &errorOutput);

    /**
     * @brief Сигнал, що випромінюється, коли процес завершився.
     * @param exitCode Код завершення процесу.
     * @param exitStatus Статус завершення.
     */
    void finished(int exitCode, QProcess::ExitStatus exitStatus);

private slots:
    // Слоти, які будуть виконуватися в окремому потоці
    void onReadyReadStandardOutput();
    void onReadyReadStandardError();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);

private:
    QThread* m_thread;   // Потік, в якому буде жити процес
    QProcess* m_process; // Сам процес, який виконує команду
};