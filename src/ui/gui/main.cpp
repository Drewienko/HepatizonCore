#include <QApplication>
#include <QWidget>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    QWidget window;
    window.setWindowTitle("HepatizonCore GUI (stub)");
    window.resize(320, 200);
    window.show();

    return app.exec();
}
