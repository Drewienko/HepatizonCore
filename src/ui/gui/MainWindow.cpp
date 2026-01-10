#include "MainWindow.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include <QApplication>
#include <QEvent>
#include <QLabel>
#include <QMessageBox>
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

    qApp->installEventFilter(this);

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
    m_secretDialog = new SecretDialog(this);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_stack = new QStackedWidget(this);
    mainLayout->addWidget(m_stack);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_loginView = new LoginView(m_service, this);
    m_stack->addWidget(m_loginView);

    connect(m_loginView, &LoginView::vaultUnlocked, this,
            [this](std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path)
            {
                m_session = session; // NOLINT(performance-unnecessary-value-param)
                m_vaultPath = path;  // NOLINT(performance-unnecessary-value-param)

                if (m_dashboardView != nullptr)
                {
                    m_dashboardView->loadVault(m_session, m_vaultPath);
                }

                switchToDashboard();
            });

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_dashboardView = new DashboardView(m_service, this);
    m_stack->addWidget(m_dashboardView);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_addSecretView = new AddSecretView(m_service, this);
    m_stack->addWidget(m_addSecretView); // Index 2

    connect(m_dashboardView, &DashboardView::addClicked,
            [this]()
            {
                if (!m_session)
                {
                    QMessageBox::warning(this, "No Vault", "Open a vault before adding secrets.");
                    return;
                }
                m_addSecretView->setVaultContext(m_session, m_vaultPath);
                m_addSecretView->resetFields();
                switchToAddSecret();
            });

    auto backToDash = [this]()
    {
        m_dashboardView->loadVault(m_session, m_vaultPath);
        switchToDashboard();
    };

    connect(m_addSecretView, &AddSecretView::cancelClicked, backToDash);
    connect(m_addSecretView, &AddSecretView::secretSaved, backToDash);

    connect(m_dashboardView, &DashboardView::lockClicked,
            [this]()
            {
                if (m_session)
                {
                    lockVault("Vault locked.");
                }
            });

    connect(m_dashboardView, &DashboardView::secretClicked,
            [this](const std::string& key)
            {
                showSecretDialog(key);
            });

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_sessionTimer = new QTimer(this);
    m_sessionTimer->setInterval(1000);
    connect(m_sessionTimer, &QTimer::timeout,
            [this]()
            {
                if (!m_session)
                {
                    return;
                }

                if (m_session->isExpired())
                {
                    lockVault("Session expired due to inactivity.");
                }
            });
    m_sessionTimer->start();
}

void MainWindow::updatePosition()
{
    QScreen* screen = QGuiApplication::primaryScreen();
    if (screen == nullptr)
    {
        return;
    }

    QRect availableRect = screen->availableGeometry();

    int x{ availableRect.right() - width() - g_screenMargin };
    int y{ availableRect.top() + g_screenMargin };

    this->move(x, y);

    this->raise();
    this->activateWindow();
    this->setFocus();
}

void MainWindow::showEvent(QShowEvent* event)
{
    QMainWindow::showEvent(event);
    // QTimer::singleShot(10, this, &MainWindow::updatePosition);
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

void MainWindow::switchToAddSecret()
{
    if (m_stack != nullptr)
    {
        m_stack->setCurrentIndex(2);
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

    m_trayMenu = new QMenu(this); // NOLINT(cppcoreguidelines-owning-memory)

    auto* toggleAction = m_trayMenu->addAction("Toggle Window");
    connect(toggleAction, &QAction::triggered,
            [this]()
            {
                if (isVisible())
                {
                    hide();
                }
                else
                {
                    show();
                    activateWindow();
                }
            });

    m_trayMenu->addSeparator();

    auto* lockAction = m_trayMenu->addAction("Lock Vault");
    connect(lockAction, &QAction::triggered,
            [this]()
            {
                if (m_session)
                {
                    lockVault("Vault locked.");
                }
            });

    m_trayMenu->addSeparator();

    auto* quitAction = m_trayMenu->addAction("Quit Hepatizon");
    connect(quitAction, &QAction::triggered, qApp, &QCoreApplication::quit);

    m_trayIcon = new QSystemTrayIcon(this); // NOLINT(cppcoreguidelines-owning-memory)
    QIcon icon(":/icon.svg");
    if (icon.isNull())
    {
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

bool MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    const auto type = event->type();
    const bool shouldTouch = (type == QEvent::KeyPress) || (type == QEvent::MouseButtonPress) ||
        (type == QEvent::Wheel) || (type == QEvent::TouchBegin) || (type == QEvent::TouchUpdate) ||
        (type == QEvent::MouseMove);

    if (shouldTouch && m_session)
    {
        m_session->touch();
    }

    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::lockVault(const QString& reason)
{
    m_session.reset();
    m_vaultPath.clear();

    if (m_dashboardView != nullptr)
    {
        m_dashboardView->loadVault(nullptr, {});
    }

    if (m_addSecretView != nullptr)
    {
        m_addSecretView->setVaultContext(nullptr, {});
    }

    if (m_secretDialog != nullptr)
    {
        m_secretDialog->close();
    }

    switchToLogin();

    if (!reason.isEmpty())
    {
        QMessageBox::information(this, "Vault Locked", reason);
    }
}

void MainWindow::showSecretDialog(const std::string& key)
{
    if (!m_session)
    {
        QMessageBox::warning(this, "No Vault", "Open a vault before viewing secrets.");
        return;
    }

    m_session->touch();

    auto result = m_service.getSecret(m_vaultPath, m_session->vault(), key);
    if (auto* secret = std::get_if<hepatizon::security::SecureString>(&result))
    {
        auto wipeSecret = hepatizon::security::scopeWipe(*secret);
        const auto view = hepatizon::security::asStringView(*secret);
        const auto value = QString::fromUtf8(view.data(), static_cast<int>(view.size()));
        const auto keyLabel = QString::fromStdString(key);

        if (m_secretDialog != nullptr)
        {
            m_secretDialog->setSecret(keyLabel, value);
            m_secretDialog->show();
            m_secretDialog->raise();
            m_secretDialog->activateWindow();
        }
        return;
    }

    const auto err = std::get<hepatizon::core::VaultError>(result);
    switch (err)
    {
    case hepatizon::core::VaultError::NotFound:
        QMessageBox::warning(this, "Not Found", "Secret not found.");
        break;
    case hepatizon::core::VaultError::AuthFailed:
        QMessageBox::critical(this, "Access Denied", "Secret authentication failed.");
        break;
    case hepatizon::core::VaultError::StorageError:
        QMessageBox::critical(this, "Storage Error", "Failed to read the secret.");
        break;
    case hepatizon::core::VaultError::CryptoError:
        QMessageBox::critical(this, "Crypto Error", "Failed to decrypt the secret.");
        break;
    case hepatizon::core::VaultError::InvalidVaultFormat:
        QMessageBox::critical(this, "Invalid Data", "The secret entry is invalid.");
        break;
    default:
        QMessageBox::critical(this, "Error", "Failed to load the secret.");
        break;
    }
}
