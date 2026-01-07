#include "AddSecretView.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QVBoxLayout>

AddSecretView::AddSecretView(hepatizon::core::VaultService& service, QWidget* parent)
    : QWidget(parent), m_service(service)
{
    setupUi();
}

void AddSecretView::setVaultContext(std::shared_ptr<hepatizon::core::UnlockedVault> vault, std::filesystem::path path)
{
    m_vault = vault;
    m_vaultPath = path;
}

void AddSecretView::resetFields()
{
    if (m_keyInput)
        m_keyInput->clear();
    if (m_valueInput)
        m_valueInput->clear();
    if (m_keyInput)
        m_keyInput->setFocus();
}

void AddSecretView::setupUi()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(30, 40, 30, 30);
    layout->setSpacing(20);

    auto* title = new QLabel("ADD NEW SECRET", this);
    title->setStyleSheet("font-size: 18px; font-weight: bold; color: #F5D163;");
    title->setAlignment(Qt::AlignCenter);
    layout->addWidget(title);

    auto* keyLabel = new QLabel("Name (e.g. Github):", this);
    m_keyInput = new QLineEdit(this);
    m_keyInput->setPlaceholderText("Enter identifier...");
    m_keyInput->setFixedHeight(40);

    layout->addWidget(keyLabel);
    layout->addWidget(m_keyInput);

    auto* valLabel = new QLabel("Password / Secret:", this);
    m_valueInput = new QLineEdit(this);
    m_valueInput->setPlaceholderText("Enter secret value...");
    m_valueInput->setEchoMode(QLineEdit::Password);
    m_valueInput->setFixedHeight(40);

    layout->addWidget(valLabel);
    layout->addWidget(m_valueInput);

    layout->addStretch();

    auto* btnLayout = new QHBoxLayout();

    m_btnCancel = new QPushButton("CANCEL", this);
    m_btnCancel->setCursor(Qt::PointingHandCursor);
    m_btnCancel->setObjectName("GhostButton");
    connect(m_btnCancel, &QPushButton::clicked, this, &AddSecretView::cancelClicked);

    m_btnSave = new QPushButton("SAVE", this);
    m_btnSave->setCursor(Qt::PointingHandCursor);
    m_btnSave->setObjectName("PrimaryButton");
    connect(m_btnSave, &QPushButton::clicked, this, &AddSecretView::onSaveClicked);

    btnLayout->addWidget(m_btnCancel);
    btnLayout->addWidget(m_btnSave);
    layout->addLayout(btnLayout);
}

void AddSecretView::onSaveClicked()
{
    if (!m_vault)
        return;

    QString key = m_keyInput->text();
    QString value = m_valueInput->text();

    if (key.isEmpty() || value.isEmpty())
    {
        QMessageBox::warning(this, "Validation", "All fields are required.");
        return;
    }

    QByteArray valueBytes = value.toUtf8();
    valueBytes.detach();
    hepatizon::security::SecureString secureVal(valueBytes.begin(), valueBytes.end());

    hepatizon::security::secureWipe(std::span{ valueBytes.data(), static_cast<size_t>(valueBytes.size()) });

    auto result = m_service.putSecret(m_vaultPath, *m_vault, key.toStdString(), secureVal);

    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        QMessageBox::critical(this, "Error", "Failed to save secret.");
    }
    else
    {
        emit secretSaved();
    }
}

void AddSecretView::onGenerateClicked()
{
    QMessageBox::information(this, "Generator", "Password Generator coming soon!");
}