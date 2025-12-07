#include <QApplication>
#include <QWidget>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    QWidget window;
    window.setWindowTitle("OnyxCitadel GUI (stub)");
    window.resize(320, 200);
    window.show();

    return app.exec();
}
