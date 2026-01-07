#include "DashboardView.hpp"
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QVBoxLayout>

DashboardView::DashboardView(hepatizon::core::VaultService& service, QWidget* parent)
    : QWidget(parent), m_service(service)
{
    setupUi();
}

void DashboardView::setupUi()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(15);

    auto* toolbarLayout = new QHBoxLayout();

    m_searchBar = new QLineEdit(this);
    m_searchBar->setPlaceholderText("Search...");
    m_searchBar->setFixedHeight(35);
    connect(m_searchBar, &QLineEdit::textChanged, this, &DashboardView::onSearchChanged);

    m_btnAdd = new QPushButton("+", this);
    m_btnAdd->setFixedSize(35, 35);
    m_btnAdd->setCursor(Qt::PointingHandCursor);
    m_btnAdd->setObjectName("IconButton");
    connect(m_btnAdd, &QPushButton::clicked, this, &DashboardView::addClicked);

    m_btnSettings = new QPushButton("⚙", this);
    m_btnSettings->setFixedSize(35, 35);
    m_btnSettings->setCursor(Qt::PointingHandCursor);
    m_btnSettings->setObjectName("IconButton");
    connect(m_btnSettings, &QPushButton::clicked, this, &DashboardView::settingsClicked);

    toolbarLayout->addWidget(m_searchBar);
    toolbarLayout->addWidget(m_btnAdd);
    toolbarLayout->addWidget(m_btnSettings);
    layout->addLayout(toolbarLayout);

    m_listWidget = new QListWidget(this);
    m_listWidget->setFrameShape(QFrame::NoFrame);
    m_listWidget->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    connect(m_listWidget, &QListWidget::itemClicked, this, &DashboardView::onItemClicked);

    layout->addWidget(m_listWidget);
}

void DashboardView::loadVault(std::shared_ptr<hepatizon::core::UnlockedVault> vault, std::filesystem::path path)
{
    m_vault = vault;
    m_vaultPath = path;
    m_searchBar->clear();
    refreshList();
}

void DashboardView::refreshList()
{
    m_listWidget->clear();
    if (!m_vault)
        return;

    auto result = m_service.listSecretKeys(m_vaultPath, *m_vault);

    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {

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
    if (item)
    {
        emit secretClicked(item->text().toStdString());
    }
}