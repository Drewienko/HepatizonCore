#include "MainWindow.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include <QApplication>
#include <QFile>
#include <QtGlobal>

int main(int argc, char* argv[])
{
#if defined(__linux__)
    if (!qEnvironmentVariableIsSet("QT_QPA_PLATFORM"))
    {
        qputenv("QT_QPA_PLATFORM", "xcb");
    }
#endif
    QApplication app(argc, argv);
    QApplication::setQuitOnLastWindowClosed(false);
    QApplication::setOrganizationName("Hepatizon");
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
    catch (const std::exception&)
    {
        return 1;
    }
}
