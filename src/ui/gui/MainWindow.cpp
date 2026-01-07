#include "MainWindow.hpp"
#include <QApplication>
#include <QLabel>
#include <QTimer>
#include <QVBoxLayout>
namespace
{
constexpr int g_defaultWidth = 360;
constexpr int g_defaultHeight = 600;
constexpr int g_screenMargin = 40;
} // namespace

MainWindow::MainWindow(hepatizon::core::VaultService& service) : m_service(service)
{
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    resize(g_defaultWidth, g_defaultHeight);

    setupUi();
    setupTray();

    updatePosition();
}

void MainWindow::setupUi()
{
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* central = new QWidget(this);
    setCentralWidget(central);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_titleBar = new TitleBar(this);
    connect(m_titleBar, &TitleBar::closeClicked, this, &QMainWindow::close);
    mainLayout->addWidget(m_titleBar);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_stack = new QStackedWidget(this);
    mainLayout->addWidget(m_stack);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_stack = new QStackedWidget(this);
    mainLayout->addWidget(m_stack);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* loginView = new LoginView(m_service, this);
    m_stack->addWidget(loginView);

    connect(loginView, &LoginView::vaultUnlocked, this,
            [this](std::shared_ptr<hepatizon::core::UnlockedVault> vault, std::filesystem::path path)
            {
                m_activeVault = vault;
                m_vaultPath = path;

                if (m_dashboardView)
                {
                    m_dashboardView->loadVault(m_activeVault, m_vaultPath);
                }

                switchToDashboard();
            });

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_dashboardView = new DashboardView(m_service, this);
    m_stack->addWidget(m_dashboardView);

    connect(m_dashboardView, &DashboardView::addClicked, []() { qDebug() << "Add clicked"; });
    connect(m_dashboardView, &DashboardView::settingsClicked, []() { qDebug() << "Settings clicked"; });
    connect(m_dashboardView, &DashboardView::secretClicked,
            [](const std::string& key) { qDebug() << "Secret clicked:" << key.c_str(); });

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_addSecretView = new AddSecretView(m_service, this);
    m_stack->addWidget(m_addSecretView); // Index 2

    connect(m_dashboardView, &DashboardView::addClicked,
            [this]()
            {
                m_addSecretView->setVaultContext(m_activeVault, m_vaultPath);
                m_addSecretView->resetFields();
                m_stack->setCurrentIndex(2);
            });

    auto backToDash = [this]()
    {
        m_dashboardView->loadVault(m_activeVault, m_vaultPath);
        switchToDashboard();
    };

    connect(m_addSecretView, &AddSecretView::cancelClicked, backToDash);
    connect(m_addSecretView, &AddSecretView::secretSaved, backToDash);
}

void MainWindow::updatePosition()
{
    QScreen* screen = QGuiApplication::primaryScreen();
    if (screen == nullptr)
        return;

    QRect availableRect = screen->availableGeometry();

    int x = availableRect.right() - width() - g_screenMargin;
    int y = availableRect.top() + g_screenMargin;

    this->move(x, y);

    this->raise();
    this->activateWindow();
    this->setFocus();
}

void MainWindow::showEvent(QShowEvent* event)
{
    QMainWindow::showEvent(event);
    QTimer::singleShot(10, this, &MainWindow::updatePosition);
}

void MainWindow::switchToDashboard()
{
    if (m_stack != nullptr)
    {
        m_stack->setCurrentIndex(1);
    }
}

void MainWindow::switchToLogin()
{
    if (m_stack != nullptr)
    {
        m_stack->setCurrentIndex(0);
    }
}

void MainWindow::setupTray()
{
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    if (!QSystemTrayIcon::isSystemTrayAvailable())
    {
        qWarning() << "System tray is not available.";
        return;
    }

    m_trayMenu = new QMenu(this);

    auto* toggleAction = m_trayMenu->addAction("Toggle Window");
    connect(toggleAction, &QAction::triggered,
            [this]()
            {
                if (isVisible())
                    hide();
                else
                {
                    show();
                    activateWindow();
                }
            });

    m_trayMenu->addSeparator();

    auto* quitAction = m_trayMenu->addAction("Quit Hepatizon");
    connect(quitAction, &QAction::triggered, qApp, &QCoreApplication::quit);

    m_trayIcon = new QSystemTrayIcon(this);
    QIcon icon(":/icon.svg");
    if (icon.isNull())
    {
        // Fallback dla WSL/Linux dev - ikona systemowa
        icon = style()->standardIcon(QStyle::SP_ComputerIcon);
    }
    m_trayIcon->setIcon(icon);
    m_trayIcon->setContextMenu(m_trayMenu);

    connect(m_trayIcon, &QSystemTrayIcon::activated,
            [this](QSystemTrayIcon::ActivationReason reason)
            {
                if (reason == QSystemTrayIcon::Trigger)
                {
                    if (isVisible())
                    {
                        hide();
                    }
                    else
                    {
                        show();
                        activateWindow();
                        raise();
                    }
                }
            });

    m_trayIcon->show();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    bool trayWorks = QSystemTrayIcon::isSystemTrayAvailable() && (m_trayIcon != nullptr) && m_trayIcon->isVisible();

    if (trayWorks)
    {
        hide();
        event->ignore();
    }
    else
    {
        event->accept();
        qApp->quit();
    }
}