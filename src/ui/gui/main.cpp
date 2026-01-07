#include "MainWindow.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include <QApplication>
#include <QFile>

int main(int argc, char* argv[])
{
    qputenv("QT_QPA_PLATFORM", "xcb");
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    QApplication::setApplicationName("HepatizonCore");

    QFile styleFile(":/theme.qss");
    if (styleFile.open(QFile::ReadOnly))
    {
        app.setStyleSheet(QString::fromUtf8(styleFile.readAll()));
    }

    try
    {
        auto crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
        auto storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
        hepatizon::core::VaultService service(*crypto, *storage);

        MainWindow window(service);
        window.show();

        return QApplication::exec();
    }
    catch (const std::exception& e)
    {
        return 1;
    }
}