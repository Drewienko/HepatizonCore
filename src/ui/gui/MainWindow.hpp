#ifndef SRC_UI_GUI_MAINWINDOW_HPP
#define SRC_UI_GUI_MAINWINDOW_HPP
#include "components/SecretDialog.hpp"
#include "components/SettingsDialog.hpp"
#include "components/TitleBar.hpp"
#include "hepatizon/core/Session.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "views/AddSecretView.hpp"
#include "views/DashboardView.hpp"
#include "views/LoginView.hpp"
#include <QCloseEvent>
#include <QMainWindow>
#include <QMenu>
#include <QScreen>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(hepatizon::core::VaultService& service);

    void switchToDashboard();
    void switchToLogin();
    void switchToAddSecret();

protected:
    void showEvent(QShowEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void setupUi();
    void updatePosition();
    void setupTray();
    void openSettings();
    void setActiveSession(std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path);
    void lockVault(const QString& reason);
    void showSecretDialog(const std::string& key);

    hepatizon::core::VaultService& m_service;

    std::shared_ptr<hepatizon::core::Session> m_session;
    std::filesystem::path m_vaultPath;

    TitleBar* m_titleBar{ nullptr };
    QStackedWidget* m_stack{ nullptr };
    QTimer* m_sessionTimer{ nullptr };
    SecretDialog* m_secretDialog{ nullptr };
    SettingsDialog* m_settingsDialog{ nullptr };

    LoginView* m_loginView{ nullptr };
    DashboardView* m_dashboardView{ nullptr };
    AddSecretView* m_addSecretView{ nullptr };

    QSystemTrayIcon* m_trayIcon{ nullptr };
    QMenu* m_trayMenu{ nullptr };
};

#endif // SRC_UI_GUI_MAINWINDOW_HPP
