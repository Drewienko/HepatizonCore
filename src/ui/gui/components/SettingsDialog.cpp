#include "SettingsDialog.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QVBoxLayout>
#include <algorithm>
#include <span>

namespace
{
constexpr int g_minutesPerHour = 60;
constexpr int g_maxTimeoutMinutes = 12 * g_minutesPerHour;
constexpr int g_maxClipboardSeconds = 300;
constexpr int g_minClipboardSeconds = 5;
} // namespace

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent)
{
    setModal(true);
    setWindowTitle("Settings");
    setupUi();
}

void SettingsDialog::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(12);

    auto* sessionBox = new QGroupBox("Auto-lock", this);
    auto* sessionLayout = new QFormLayout(sessionBox);

    m_disableTimeout = new QCheckBox("Disable auto-lock", sessionBox);
    connect(m_disableTimeout, &QCheckBox::toggled, this, &SettingsDialog::onDisableTimeoutToggled);
    sessionLayout->addRow(m_disableTimeout);

    m_timeoutMinutes = new QSpinBox(sessionBox);
    m_timeoutMinutes->setRange(1, g_maxTimeoutMinutes);
    m_timeoutMinutes->setSuffix(" min");
    sessionLayout->addRow("Timeout:", m_timeoutMinutes);

    mainLayout->addWidget(sessionBox);

    auto* clipboardBox = new QGroupBox("Clipboard", this);
    auto* clipboardLayout = new QFormLayout(clipboardBox);
    m_clipboardSeconds = new QSpinBox(clipboardBox);
    m_clipboardSeconds->setRange(g_minClipboardSeconds, g_maxClipboardSeconds);
    m_clipboardSeconds->setSuffix(" sec");
    clipboardLayout->addRow("Auto-clear after:", m_clipboardSeconds);
    mainLayout->addWidget(clipboardBox);

    auto* passwordBox = new QGroupBox("Change master password", this);
    auto* passwordLayout = new QFormLayout(passwordBox);

    m_newPassword = new QLineEdit(passwordBox);
    m_newPassword->setEchoMode(QLineEdit::Password);

    m_confirmPassword = new QLineEdit(passwordBox);
    m_confirmPassword->setEchoMode(QLineEdit::Password);

    passwordLayout->addRow("New password:", m_newPassword);
    passwordLayout->addRow("Confirm:", m_confirmPassword);
    mainLayout->addWidget(passwordBox);

    auto* buttonsLayout = new QHBoxLayout();
    buttonsLayout->addStretch();

    m_cancelButton = new QPushButton("Cancel", this);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    buttonsLayout->addWidget(m_cancelButton);

    m_saveButton = new QPushButton("Save", this);
    connect(m_saveButton, &QPushButton::clicked, this, &SettingsDialog::onSaveClicked);
    buttonsLayout->addWidget(m_saveButton);

    mainLayout->addLayout(buttonsLayout);
}

void SettingsDialog::setSessionTimeoutSeconds(int seconds)
{
    if (seconds <= 0)
    {
        m_disableTimeout->setChecked(true);
        m_timeoutMinutes->setValue(1);
        m_timeoutMinutes->setEnabled(false);
        return;
    }

    const int minutes = std::max(1, seconds / 60);
    m_disableTimeout->setChecked(false);
    m_timeoutMinutes->setEnabled(true);
    m_timeoutMinutes->setValue(minutes);
}

void SettingsDialog::setClipboardTimeoutMs(int ms)
{
    const int seconds = std::clamp(ms / 1000, g_minClipboardSeconds, g_maxClipboardSeconds);
    m_clipboardSeconds->setValue(seconds);
}

int SettingsDialog::sessionTimeoutSeconds() const noexcept
{
    if (m_disableTimeout->isChecked())
    {
        return 0;
    }
    return m_timeoutMinutes->value() * 60;
}

int SettingsDialog::clipboardTimeoutMs() const noexcept
{
    return m_clipboardSeconds->value() * 1000;
}

std::optional<hepatizon::security::SecureString> SettingsDialog::takeNewPassword() noexcept
{
    auto out = std::move(m_pendingPassword);
    m_pendingPassword.reset();
    return out;
}

void SettingsDialog::onDisableTimeoutToggled(bool checked)
{
    if (m_timeoutMinutes != nullptr)
    {
        m_timeoutMinutes->setEnabled(!checked);
    }
}

void SettingsDialog::clearPasswordFields()
{
    if (m_newPassword != nullptr)
    {
        m_newPassword->clear();
    }
    if (m_confirmPassword != nullptr)
    {
        m_confirmPassword->clear();
    }
}

void SettingsDialog::onSaveClicked()
{
    m_pendingPassword.reset();

    const QString newPass = m_newPassword->text();
    const QString confirmPass = m_confirmPassword->text();

    if (!newPass.isEmpty() || !confirmPass.isEmpty())
    {
        if (newPass.isEmpty() || confirmPass.isEmpty())
        {
            QMessageBox::warning(this, "Validation", "Both password fields are required.");
            return;
        }
        if (newPass != confirmPass)
        {
            QMessageBox::warning(this, "Validation", "Passwords do not match.");
            return;
        }

        QByteArray bytes = newPass.toUtf8();
        QString wipeNew = newPass;
        QString wipeConfirm = confirmPass;
        wipeNew.fill(QChar(0));
        wipeConfirm.fill(QChar(0));
        bytes.detach();

        hepatizon::security::SecureString secure(bytes.begin(), bytes.end());
        hepatizon::security::secureWipe(std::span{ bytes.data(), static_cast<size_t>(bytes.size()) });

        m_pendingPassword = std::move(secure);
    }

    clearPasswordFields();
    accept();
}
