#ifndef SRC_UI_GUI_MAINWINDOW_HPP
#define SRC_UI_GUI_MAINWINDOW_HPP
#include "components/TitleBar.hpp"
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

private:
    void setupUi();
    void updatePosition();
    void setupTray();

    hepatizon::core::VaultService& m_service;

    std::shared_ptr<hepatizon::core::UnlockedVault> m_activeVault;
    std::filesystem::path m_vaultPath;

    TitleBar* m_titleBar{ nullptr };
    QStackedWidget* m_stack{ nullptr };

    LoginView* m_loginView{ nullptr };
    DashboardView* m_dashboardView{ nullptr };
    AddSecretView* m_addSecretView{ nullptr };

    QSystemTrayIcon* m_trayIcon{ nullptr };
    QMenu* m_trayMenu{ nullptr };
};

#endif // SRC_UI_GUI_MAINWINDOW_HPP
