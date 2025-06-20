//  CommandRunner.cpp

#include "CommandRunner.hpp"
#include <QDebug>

CommandRunner::CommandRunner(QObject *parent)
    : QObject(parent)
{
    m_thread = new QThread(this);
    m_process = new QProcess();

    m_process->moveToThread(m_thread);

    // З'єднуємо сигнали від QProcess зі слотами нашого CommandRunner.
    // Оскільки m_process живе в іншому потоці, ці з'єднання будуть типу QueuedConnection.
    connect(m_process, &QProcess::readyReadStandardOutput, this, &CommandRunner::onReadyReadStandardOutput);
    connect(m_process, &QProcess::readyReadStandardError, this, &CommandRunner::onReadyReadStandardError);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), 
            this, &CommandRunner::onProcessFinished);
    connect(m_process, qOverload<QProcess::ProcessError>(&QProcess::errorOccurred), this, &CommandRunner::onProcessError);
    
    // Важливо! Потрібно обробити завершення потоку, щоб коректно видалити процес.
    connect(m_thread, &QThread::finished, m_process, &QObject::deleteLater);

    // Запускаємо потік. Тепер він готовий приймати події.
    m_thread->start();
}

CommandRunner::~CommandRunner()
{
    // Зупиняємо процес, якщо він ще працює
    stopCommand();
    
    // Зупиняємо потік і чекаємо його завершення
    m_thread->quit();
    m_thread->wait(); // Чекаємо, поки потік дійсно завершиться
}

void CommandRunner::startCommand(const QString &program, const QStringList &arguments)
{
    if (m_process->state() != QProcess::NotRunning) {
        qWarning() << "Process is already running.";
        return;
    }

    // Використовуємо QMetaObject::invokeMethod для безпечного виклику методу
    // в іншому потоці. Це гарантує, що start() буде викликано в потоці m_thread.
    QMetaObject::invokeMethod(m_process, "start", Qt::QueuedConnection,
                              Q_ARG(QString, program),
                              Q_ARG(QStringList, arguments));
}

void CommandRunner::stopCommand()
{
    if (m_process->state() == QProcess::NotRunning) {
        return;
    }
    
    // Аналогічно, викликаємо terminate() безпечно через систему мета-об'єктів
    QMetaObject::invokeMethod(m_process, "terminate", Qt::QueuedConnection);
    
    // terminate - це "м'яка" зупинка (надсилає SIGTERM). Якщо процес не реагує,
    // можна використати "kill()", що є більш жорстким (SIGKILL).
    // Для цього можна додати таймер.
    // QMetaObject::invokeMethod(m_process, "kill", Qt::QueuedConnection);
}

void CommandRunner::onReadyReadStandardOutput()
{
    // Цей слот виконується в потоці m_thread
    const QByteArray data = m_process->readAllStandardOutput();
    // Випромінюємо сигнал, який отримає головний потік
    emit outputReceived(QString::fromUtf8(data));
}

void CommandRunner::onReadyReadStandardError()
{
    // Цей слот виконується в потоці m_thread
    const QByteArray data = m_process->readAllStandardError();
    emit errorOutputReceived(QString::fromUtf8(data));
}

void CommandRunner::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    qDebug() << "Process finished with exit code" << exitCode;
    emit finished(exitCode, exitStatus);
}

void CommandRunner::onProcessError(QProcess::ProcessError error)
{
    // Обробка помилок запуску процесу
    qWarning() << "Process error:" << error << m_process->errorString();
}
