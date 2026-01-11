#include "AddSecretView.hpp"
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QVBoxLayout>

namespace
{
constexpr int g_marginV = 40;
constexpr int g_marginH = 30;
constexpr int g_spacing = 20;
constexpr int g_inputHeight = 40;
} // namespace

AddSecretView::AddSecretView(hepatizon::core::VaultService& service, QWidget* parent)
    : QWidget(parent), m_service(service)
{
    setupUi();
}

void AddSecretView::setVaultContext(std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path)
{
    m_session = std::move(session);
    m_vaultPath = std::move(path);
}

void AddSecretView::resetFields()
{
    if (m_keyInput != nullptr)
    {
        m_keyInput->clear();
    }
    if (m_valueInput != nullptr)
    {
        m_valueInput->clear();
    }
    if (m_keyInput != nullptr)
    {
        m_keyInput->setFocus();
    }
}

void AddSecretView::setupUi()
{
    auto* layout = new QVBoxLayout(this); // NOLINT(cppcoreguidelines-owning-memory)
    layout->setContentsMargins(g_marginH, g_marginV, g_marginH, g_marginH);
    layout->setSpacing(g_spacing);

    auto* title = new QLabel("ADD NEW SECRET", this); // NOLINT(cppcoreguidelines-owning-memory)
    title->setStyleSheet("font-size: 18px; font-weight: bold; color: #F5D163;");
    title->setAlignment(Qt::AlignCenter);
    layout->addWidget(title);

    auto* keyLabel = new QLabel("Name (e.g. Github):", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_keyInput = new QLineEdit(this);                         // NOLINT(cppcoreguidelines-owning-memory)
    m_keyInput->setPlaceholderText("Enter identifier...");
    m_keyInput->setFixedHeight(g_inputHeight);

    layout->addWidget(keyLabel);
    layout->addWidget(m_keyInput);

    auto* valLabel = new QLabel("Password / Secret:", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_valueInput = new QLineEdit(this);                      // NOLINT(cppcoreguidelines-owning-memory)
    m_valueInput->setPlaceholderText("Enter secret value...");
    m_valueInput->setEchoMode(QLineEdit::Password);
    m_valueInput->setFixedHeight(g_inputHeight);

    layout->addWidget(valLabel);
    layout->addWidget(m_valueInput);

    layout->addStretch();

    auto* btnLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)

    m_btnCancel = new QPushButton("CANCEL", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_btnCancel->setCursor(Qt::PointingHandCursor);
    m_btnCancel->setObjectName("GhostButton");
    connect(m_btnCancel, &QPushButton::clicked,
            [this]()
            {
                resetFields();
                emit cancelClicked();
            });

    m_btnSave = new QPushButton("SAVE", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_btnSave->setCursor(Qt::PointingHandCursor);
    m_btnSave->setObjectName("PrimaryButton");
    connect(m_btnSave, &QPushButton::clicked, this, &AddSecretView::onSaveClicked);

    btnLayout->addWidget(m_btnCancel);
    btnLayout->addWidget(m_btnSave);
    layout->addLayout(btnLayout);
}

void AddSecretView::onSaveClicked()
{
    if (!m_session)
    {
        QMessageBox::warning(this, "No Vault", "Open a vault before saving secrets.");
        return;
    }

    QString key = m_keyInput->text();
    QString value = m_valueInput->text();

    if (key.isEmpty() || value.isEmpty())
    {
        QMessageBox::warning(this, "Validation", "All fields are required.");
        return;
    }

    QByteArray valueBytes = value.toUtf8();
    value.fill(QChar(0));
    value.clear();
    valueBytes.detach();
    hepatizon::security::SecureString secureVal(valueBytes.begin(), valueBytes.end());

    hepatizon::security::secureWipe(std::span{ valueBytes.data(), static_cast<size_t>(valueBytes.size()) });
    if (m_valueInput != nullptr)
    {
        m_valueInput->clear();
    }

    auto result = m_service.putSecret(m_vaultPath, m_session->vault(), key.toStdString(), secureVal);

    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        QMessageBox::critical(this, "Error", "Failed to save secret.");
    }
    else
    {
        resetFields();
        emit secretSaved();
    }
}

void AddSecretView::onGenerateClicked()
{
    QMessageBox::information(this, "Generator", "Password Generator coming soon!");
}
