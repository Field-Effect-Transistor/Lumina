#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Створюємо віджет, який стане вікном верхнього рівня
    QWidget *window = new QWidget();
    window->setWindowTitle("Просте вікно QWidget");
    window->resize(300, 200);

    // Додаємо кнопку до вікна
    QPushButton *button = new QPushButton("Натисни мене", window);
    // Розміщення кнопки (простий варіант без layout'у)
    // button->setGeometry(100, 80, 100, 30); // x, y, width, height

    // Краще використовувати Layouts
    QVBoxLayout *layout = new QVBoxLayout(window);
    layout->addWidget(button);
    window->setLayout(layout);


    window->show(); // Показати вікно

    return app.exec();
}