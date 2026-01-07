#include "LoginView.hpp"
#include "hepatizon/security/ScopeWipe.hpp"

#include <QDir>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QStandardPaths>
#include <QVBoxLayout>

namespace
{
constexpr int g_inputHeight = 40;
}

LoginView::LoginView(hepatizon::core::VaultService& service, QWidget* parent) : QWidget(parent), m_service(service)
{
    setupUi();
}

void LoginView::setupUi()
{

    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(15);
    layout->setContentsMargins(30, 40, 30, 30);

    auto* logoLabel = new QLabel("HEPATIZON", this);
    logoLabel->setAlignment(Qt::AlignCenter);
    logoLabel->setStyleSheet(
        "font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #F5D163; margin-bottom: 20px;");
    layout->addWidget(logoLabel);

    auto* pathLayout = new QHBoxLayout();
    m_pathInput = new QLineEdit(this);
    m_pathInput->setPlaceholderText("Path to vault.db");
    m_pathInput->setFixedHeight(g_inputHeight);

    QString docsPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    m_pathInput->setText(QDir(docsPath).filePath("vault.db"));

    auto* browseBtn = new QPushButton("...", this);
    browseBtn->setFixedSize(40, g_inputHeight);
    connect(browseBtn, &QPushButton::clicked, this, &LoginView::onBrowseClicked);

    pathLayout->addWidget(m_pathInput);
    pathLayout->addWidget(browseBtn);
    layout->addLayout(pathLayout);

    auto* passLayout = new QHBoxLayout();
    passLayout->setSpacing(5);

    m_passInput = new QLineEdit(this);
    m_passInput->setPlaceholderText("Master Password");
    m_passInput->setEchoMode(QLineEdit::Password);
    m_passInput->setFixedHeight(g_inputHeight);

    connect(m_passInput, &QLineEdit::returnPressed, this, &LoginView::onUnlockClicked);

    m_visibilityBtn = new QPushButton("👁", this);
    m_visibilityBtn->setFixedSize(40, g_inputHeight);
    m_visibilityBtn->setCheckable(true);
    m_visibilityBtn->setCursor(Qt::PointingHandCursor);
    connect(m_visibilityBtn, &QPushButton::toggled, this, &LoginView::togglePasswordVisibility);

    passLayout->addWidget(m_passInput);
    passLayout->addWidget(m_visibilityBtn);
    layout->addLayout(passLayout);

    layout->addStretch();

    auto* btnLayout = new QHBoxLayout();
    auto* createBtn = new QPushButton("CREATE NEW", this);
    auto* unlockBtn = new QPushButton("UNLOCK", this);

    unlockBtn->setObjectName("PrimaryButton");
    unlockBtn->setFixedHeight(45);
    createBtn->setFixedHeight(45);

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
    QString fileName = QFileDialog::getSaveFileName(this, "Select Vault File", m_pathInput->text(),
                                                    "Vault Files (*.db);;All Files (*)");

    if (!fileName.isEmpty())
    {
        m_pathInput->setText(fileName);
    }
}

void LoginView::togglePasswordVisibility()
{
    if (m_visibilityBtn->isChecked())
    {
        m_passInput->setEchoMode(QLineEdit::Normal);
    }
    else
    {
        m_passInput->setEchoMode(QLineEdit::Password);
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
    std::string path = m_pathInput->text().toStdString();

    if (!m_service.vaultExists(path))
    {
        QMessageBox::warning(this, "Error", "Vault file not found. Create a new one?");
        return;
    }

    auto action = [&](const hepatizon::security::SecureString& key)
    {
        auto result = m_service.openVault(path, key);

        if (auto* vault = std::get_if<hepatizon::core::UnlockedVault>(&result))
        {
            auto vaultPtr = std::make_shared<hepatizon::core::UnlockedVault>(std::move(*vault));
            emit vaultUnlocked(vaultPtr, path);
        }
        else
        {
            QMessageBox::critical(this, "Access Denied", "Invalid password or corrupted vault.");
        }
    };

    if (!processPasswordAndExecute(action))
    {
        QMessageBox::warning(this, "Validation", "Password cannot be empty.");
    }
}

void LoginView::onCreateClicked()
{
    std::string path = m_pathInput->text().toStdString();

    if (m_service.vaultExists(path))
    {
        auto reply =
            QMessageBox::question(this, "Confirm", "Vault exists. Overwrite?", QMessageBox::Yes | QMessageBox::No);
        if (reply != QMessageBox::Yes)
            return;
    }

    auto action = [&](const hepatizon::security::SecureString& key)
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
                auto vaultPtr = std::make_shared<hepatizon::core::UnlockedVault>(std::move(*vault));
                emit vaultUnlocked(vaultPtr, path);
            }
        }
    };

    if (!processPasswordAndExecute(action))
    {
        QMessageBox::warning(this, "Validation", "Password cannot be empty.");
    }
}