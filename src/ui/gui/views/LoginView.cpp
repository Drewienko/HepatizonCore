#include "LoginView.hpp"
#include "GuiSettings.hpp"
#include "hepatizon/core/Session.hpp"

#include <QDir>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QStandardPaths>
#include <QVBoxLayout>
#include <QtGlobal>
#include <chrono>

namespace
{
constexpr int g_inputHeight = 40;
constexpr int g_marginH = 30;
constexpr int g_marginV = 40;
constexpr int g_spacing = 15;
constexpr int g_btnHeight = 45;
constexpr int g_passSpacing = 5;
constexpr int g_iconBtnWidth = 40;
std::filesystem::path toVaultPath(const QString& input)
{
#if defined(Q_OS_WIN)
    return std::filesystem::path{ input.toStdWString() };
#else
    return std::filesystem::path{ input.toStdString() };
#endif
}

std::chrono::seconds sessionTimeout()
{
    return std::chrono::seconds{ hepatizon::ui::readSessionTimeoutSeconds() };
}
} // namespace

LoginView::LoginView(hepatizon::core::VaultService& service, QWidget* parent) : QWidget(parent), m_service(service)
{
    setupUi();
}

void LoginView::setupUi()
{

    auto* layout = new QVBoxLayout(this); // NOLINT(cppcoreguidelines-owning-memory)
    layout->setSpacing(g_spacing);
    layout->setContentsMargins(g_marginH, g_marginV, g_marginH, g_marginH);

    auto* logoLabel = new QLabel("HEPATIZON", this); // NOLINT(cppcoreguidelines-owning-memory)
    logoLabel->setAlignment(Qt::AlignCenter);
    logoLabel->setStyleSheet(
        "font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #F5D163; margin-bottom: 20px;");
    layout->addWidget(logoLabel);

    auto* pathLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)
    m_pathInput = new QLineEdit(this);    // NOLINT(cppcoreguidelines-owning-memory)
    m_pathInput->setPlaceholderText("Vault directory");
    m_pathInput->setFixedHeight(g_inputHeight);

    QString docsPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    m_pathInput->setText(QDir(docsPath).filePath("HepatizonVault"));

    auto* browseBtn = new QPushButton(QIcon(":/icons/folder.svg"), "", this); // NOLINT(cppcoreguidelines-owning-memory)
    browseBtn->setFixedSize(g_iconBtnWidth, g_inputHeight);
    connect(browseBtn, &QPushButton::clicked, this, &LoginView::onBrowseClicked);

    pathLayout->addWidget(m_pathInput);
    pathLayout->addWidget(browseBtn);
    layout->addLayout(pathLayout);

    auto* passLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)
    passLayout->setSpacing(g_passSpacing);

    m_passInput = new QLineEdit(this); // NOLINT(cppcoreguidelines-owning-memory)
    m_passInput->setPlaceholderText("Master Password");
    m_passInput->setEchoMode(QLineEdit::Password);
    m_passInput->setFixedHeight(g_inputHeight);

    connect(m_passInput, &QLineEdit::returnPressed, this, &LoginView::onUnlockClicked);

    m_visibilityBtn =                                            // NOLINT(cppcoreguidelines-owning-memory)
        new QPushButton(QIcon(":/icons/eye-off.svg"), "", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_visibilityBtn->setFixedSize(g_iconBtnWidth, g_inputHeight);
    m_visibilityBtn->setCheckable(true);
    m_visibilityBtn->setCursor(Qt::PointingHandCursor);
    connect(m_visibilityBtn, &QPushButton::toggled, this, &LoginView::togglePasswordVisibility);

    passLayout->addWidget(m_passInput);
    passLayout->addWidget(m_visibilityBtn);
    layout->addLayout(passLayout);

    layout->addStretch();

    auto* btnLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)
    auto* createBtn =
        new QPushButton(QIcon(":/icons/add.svg"), "CREATE NEW", this); // NOLINT(cppcoreguidelines-owning-memory)
    auto* unlockBtn =
        new QPushButton(QIcon(":/icons/key.svg"), "UNLOCK", this); // NOLINT(cppcoreguidelines-owning-memory)

    unlockBtn->setObjectName("PrimaryButton");
    unlockBtn->setFixedHeight(g_btnHeight);
    createBtn->setFixedHeight(g_btnHeight);

    connect(createBtn, &QPushButton::clicked, this, &LoginView::onCreateClicked);
    connect(unlockBtn, &QPushButton::clicked, this, &LoginView::onUnlockClicked);

    btnLayout->addWidget(createBtn);
    btnLayout->addWidget(unlockBtn);
    layout->addLayout(btnLayout);

    m_pathInput->setObjectName("PathInput");
    m_passInput->setObjectName("PassInput");
    unlockBtn->setObjectName("UnlockButton");
    createBtn->setObjectName("CreateButton");
}

void LoginView::onBrowseClicked()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Select Vault Directory", m_pathInput->text());

    if (!dir.isEmpty())
    {
        m_pathInput->setText(dir);
    }
}

void LoginView::togglePasswordVisibility()
{
    if (m_visibilityBtn->isChecked())
    {
        m_passInput->setEchoMode(QLineEdit::Normal);
        m_visibilityBtn->setIcon(QIcon(":/icons/eye.svg"));
    }
    else
    {
        m_passInput->setEchoMode(QLineEdit::Password);
        m_visibilityBtn->setIcon(QIcon(":/icons/eye-off.svg"));
    }
}

template <typename Func> bool LoginView::processPasswordAndExecute(Func action)
{
    QString password = m_passInput->text();
    if (password.isEmpty())
    {
        return false;
    }

    QByteArray authData = password.toUtf8();
    password.fill(QChar(0));
    password.clear();
    authData.detach();
    hepatizon::security::SecureString secureKey(authData.begin(), authData.end());

    if (!authData.isEmpty())
    {
        hepatizon::security::secureWipe(std::span{ authData.data(), static_cast<size_t>(authData.size()) });
    }
    m_passInput->clear();

    action(secureKey);
    return true;
}

void LoginView::onUnlockClicked()
{
    std::filesystem::path path = toVaultPath(m_pathInput->text());

    if (path.empty())
    {
        QMessageBox::warning(this, "Validation", "Vault directory is required.");
        return;
    }

    if (!m_service.vaultExists(path))
    {
        QMessageBox::warning(this, "Error", "Vault directory not found. Create a new one?");
        return;
    }

    auto action = [&](const hepatizon::security::SecureString& key)
    {
        try
        {
            auto result = m_service.openVault(path, key);

            if (auto* vault = std::get_if<hepatizon::core::UnlockedVault>(&result))
            {
                auto session = std::make_shared<hepatizon::core::Session>(std::move(*vault), sessionTimeout());
                emit vaultUnlocked(session, path);
            }
            else
            {
                QMessageBox::critical(this, "Access Denied", "Invalid password or corrupted vault.");
            }
        }
        catch (const std::exception& e)
        {
            QMessageBox::critical(this, "Error", e.what());
        }
    };

    if (!processPasswordAndExecute(action))
    {
        QMessageBox::warning(this, "Validation", "Password cannot be empty.");
    }
}

void LoginView::onCreateClicked()
{
    std::filesystem::path path = toVaultPath(m_pathInput->text());

    if (path.empty())
    {
        QMessageBox::warning(this, "Validation", "Vault directory is required.");
        return;
    }

    if (m_service.vaultExists(path))
    {
        QMessageBox::information(this, "Vault Exists", "Vault already exists. Use UNLOCK instead.");
        return;
    }

    auto action = [&](const hepatizon::security::SecureString& key)
    {
        try
        {
            auto result = m_service.createVault(path, key);

            if (std::holds_alternative<hepatizon::core::VaultError>(result))
            {
                QMessageBox::critical(this, "Error", "Failed to create vault.");
            }
            else
            {
                auto openRes = m_service.openVault(path, key);
                if (auto* vault = std::get_if<hepatizon::core::UnlockedVault>(&openRes))
                {
                    auto session = std::make_shared<hepatizon::core::Session>(std::move(*vault), sessionTimeout());
                    emit vaultUnlocked(session, path);
                }
                else
                {
                    QMessageBox::critical(this, "Error", "Vault created but failed to unlock.");
                }
            }
        }
        catch (const std::exception& e)
        {
            QMessageBox::critical(this, "Error", e.what());
        }
    };

    if (!processPasswordAndExecute(action))
    {
        QMessageBox::warning(this, "Validation", "Password cannot be empty.");
    }
}
