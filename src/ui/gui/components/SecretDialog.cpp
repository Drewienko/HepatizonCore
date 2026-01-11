#include "SecretDialog.hpp"

#include <QClipboard>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <algorithm>

namespace
{
constexpr int g_copyTimeoutMs = 15000;
constexpr int g_margin = 20;
constexpr int g_spacing = 12;
constexpr int g_btnSpacing = 8;
constexpr int g_inputHeight = 36;
constexpr int g_btnSize = 36;
} // namespace

SecretDialog::SecretDialog(QWidget* parent)
    : QDialog(parent), m_keyLabel(new QLabel(this)), // NOLINT(cppcoreguidelines-owning-memory)
      m_valueInput(new QLineEdit(this)),             // NOLINT(cppcoreguidelines-owning-memory)
      m_clipboardTimer(new QTimer(this)),            // NOLINT(cppcoreguidelines-owning-memory)
      m_copyTimeoutMs(g_copyTimeoutMs)
{
    setModal(true);
    setWindowTitle("Secret");

    auto* mainLayout = new QVBoxLayout(this); // NOLINT(cppcoreguidelines-owning-memory)
    mainLayout->setContentsMargins(g_margin, g_margin, g_margin, g_margin);
    mainLayout->setSpacing(g_spacing);

    m_keyLabel->setStyleSheet("font-weight: bold; font-size: 16px;");
    mainLayout->addWidget(m_keyLabel);

    auto* valueLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)
    m_valueInput->setReadOnly(true);
    m_valueInput->setEchoMode(QLineEdit::Password);
    m_valueInput->setFixedHeight(g_inputHeight);
    valueLayout->addWidget(m_valueInput);

    m_revealBtn = new QPushButton("👁", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_revealBtn->setCheckable(true);
    m_revealBtn->setFixedSize(g_btnSize, g_btnSize);
    connect(m_revealBtn, &QPushButton::toggled, this, &SecretDialog::onToggleReveal);
    valueLayout->addWidget(m_revealBtn);

    mainLayout->addLayout(valueLayout);

    auto* btnLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)
    btnLayout->setSpacing(g_btnSpacing);

    m_copyBtn = new QPushButton("Copy", this); // NOLINT(cppcoreguidelines-owning-memory)
    connect(m_copyBtn, &QPushButton::clicked, this, &SecretDialog::onCopyClicked);
    btnLayout->addWidget(m_copyBtn);

    btnLayout->addStretch();

    m_closeBtn = new QPushButton("Close", this); // NOLINT(cppcoreguidelines-owning-memory)
    connect(m_closeBtn, &QPushButton::clicked,
            [this]()
            {
                clearSensitiveFields();
                close();
            });
    btnLayout->addWidget(m_closeBtn);

    mainLayout->addLayout(btnLayout);

    m_clipboardTimer->setSingleShot(true);
    connect(m_clipboardTimer, &QTimer::timeout, this, &SecretDialog::clearClipboardIfUnchanged);
}

void SecretDialog::setSecret(const QString& key, const QString& value)
{
    m_keyLabel->setText(key);
    m_valueInput->setText(value);
    m_valueInput->setEchoMode(QLineEdit::Password);
    m_revealBtn->setChecked(false);
}

void SecretDialog::setClipboardTimeoutMs(int timeoutMs) noexcept
{
    m_copyTimeoutMs = std::max(timeoutMs, 0);
}

void SecretDialog::onCopyClicked()
{
    auto* clipboard = QGuiApplication::clipboard();
    if (clipboard == nullptr)
    {
        return;
    }

    clipboard->setText(m_valueInput->text());
    if (m_copyTimeoutMs > 0)
    {
        m_clipboardTimer->start(m_copyTimeoutMs);
    }
}

void SecretDialog::onToggleReveal(bool checked)
{
    m_valueInput->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
}

void SecretDialog::clearClipboardIfUnchanged()
{
    auto* clipboard = QGuiApplication::clipboard();
    if (clipboard == nullptr)
    {
        return;
    }

    if (clipboard->text() == m_valueInput->text())
    {
        clipboard->clear();
    }
}

void SecretDialog::clearSensitiveFields()
{
    if (m_valueInput != nullptr)
    {
        m_valueInput->clear();
    }
    clearClipboardIfUnchanged();
}
