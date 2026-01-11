#include "DashboardView.hpp"
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QVBoxLayout>

namespace
{
constexpr int g_margin = 20;
constexpr int g_spacing = 15;
constexpr int g_iconSize = 35;
} // namespace

DashboardView::DashboardView(hepatizon::core::VaultService& service, QWidget* parent)
    : QWidget(parent), m_service(service)
{
    setupUi();
}

void DashboardView::setupUi()
{
    auto* layout = new QVBoxLayout(this); // NOLINT(cppcoreguidelines-owning-memory)
    layout->setContentsMargins(g_margin, g_margin, g_margin, g_margin);
    layout->setSpacing(g_spacing);

    auto* toolbarLayout = new QHBoxLayout(); // NOLINT(cppcoreguidelines-owning-memory)

    m_searchBar = new QLineEdit(this); // NOLINT(cppcoreguidelines-owning-memory)
    m_searchBar->setPlaceholderText("Search...");
    m_searchBar->setFixedHeight(g_iconSize);
    connect(m_searchBar, &QLineEdit::textChanged, this, &DashboardView::onSearchChanged);

    m_btnAdd = new QPushButton(QIcon(":/icons/add.svg"), "", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_btnAdd->setFixedSize(g_iconSize, g_iconSize);
    m_btnAdd->setCursor(Qt::PointingHandCursor);
    m_btnAdd->setObjectName("IconButton");
    connect(m_btnAdd, &QPushButton::clicked, this, &DashboardView::addClicked);

    m_btnLock = new QPushButton(QIcon(":/icons/lock.svg"), "", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_btnLock->setFixedSize(g_iconSize, g_iconSize);
    m_btnLock->setCursor(Qt::PointingHandCursor);
    m_btnLock->setObjectName("IconButton");
    connect(m_btnLock, &QPushButton::clicked, this, &DashboardView::lockClicked);

    m_btnSettings = new QPushButton(QIcon(":/icons/settings.svg"), "", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_btnSettings->setFixedSize(g_iconSize, g_iconSize);
    m_btnSettings->setCursor(Qt::PointingHandCursor);
    m_btnSettings->setObjectName("IconButton");
    connect(m_btnSettings, &QPushButton::clicked, this, &DashboardView::settingsClicked);

    m_btnDelete = new QPushButton(QIcon(":/icons/delete.svg"), "", this); // NOLINT(cppcoreguidelines-owning-memory)
    m_btnDelete->setFixedSize(g_iconSize, g_iconSize);
    m_btnDelete->setCursor(Qt::PointingHandCursor);
    m_btnDelete->setObjectName("IconButton");
    m_btnDelete->setEnabled(false);
    connect(m_btnDelete, &QPushButton::clicked, this, &DashboardView::onDeleteClicked);

    toolbarLayout->addWidget(m_searchBar);
    toolbarLayout->addWidget(m_btnAdd);
    toolbarLayout->addWidget(m_btnDelete);
    toolbarLayout->addWidget(m_btnLock);
    toolbarLayout->addWidget(m_btnSettings);
    layout->addLayout(toolbarLayout);

    m_listWidget = new QListWidget(this); // NOLINT(cppcoreguidelines-owning-memory)
    m_listWidget->setFrameShape(QFrame::NoFrame);
    m_listWidget->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    connect(m_listWidget, &QListWidget::itemClicked, this, &DashboardView::onItemClicked);

    layout->addWidget(m_listWidget);
}

void DashboardView::loadVault(std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path)
{
    m_session = std::move(session);
    m_vaultPath = std::move(path);
    m_searchBar->clear();
    refreshList();
    m_btnDelete->setEnabled(false);
}

void DashboardView::refreshList()
{
    m_listWidget->clear();
    if (!m_session)
    {
        return;
    }

    auto result = m_service.listSecretKeys(m_vaultPath, m_session->vault());

    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        QMessageBox::critical(this, "Error", "Failed to load vault entries.");
        return;
    }

    const auto& keys = std::get<std::vector<std::string>>(result);
    for (const auto& key : keys)
    {
        auto* item = new QListWidgetItem(QString::fromStdString(key));
        m_listWidget->addItem(item);
    }
}

void DashboardView::onSearchChanged(const QString& text)
{
    for (int i = 0; i < m_listWidget->count(); ++i)
    {
        auto* item = m_listWidget->item(i);
        bool matches = item->text().contains(text, Qt::CaseInsensitive);
        item->setHidden(!matches);
    }
}

void DashboardView::onItemClicked(QListWidgetItem* item)
{
    m_btnDelete->setEnabled(item != nullptr);
    if (item != nullptr)
    {
        emit secretClicked(item->text().toStdString());
    }
}

void DashboardView::onDeleteClicked()
{
    auto* selectedItem = m_listWidget->currentItem();
    if (selectedItem == nullptr)
    {
        return;
    }

    const auto reply = QMessageBox::question(this, "Confirm Delete",
                                             tr("Are you sure you want to delete '%1'?").arg(selectedItem->text()),
                                             QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }

    const auto key = selectedItem->text().toStdString();
    auto result = m_service.deleteSecret(m_vaultPath, m_session->vault(), key);

    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        QMessageBox::critical(this, "Error", "Failed to delete secret.");
        return;
    }

    refreshList();
    m_btnDelete->setEnabled(false);
}
