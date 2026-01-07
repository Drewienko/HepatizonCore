#ifndef SRC_UI_GUI_VIEWS_DASHBOARDVIEW_HPP
#define SRC_UI_GUI_VIEWS_DASHBOARDVIEW_HPP

#include "hepatizon/core/VaultService.hpp"
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QWidget>
#include <filesystem>
#include <memory>

class DashboardView : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardView(hepatizon::core::VaultService& service, QWidget* parent = nullptr);

    void loadVault(std::shared_ptr<hepatizon::core::UnlockedVault> vault, std::filesystem::path path);

signals:
    void secretClicked(const std::string& key);
    void addClicked();
    void settingsClicked();

private slots:
    void onSearchChanged(const QString& text);
    void onItemClicked(QListWidgetItem* item);

private:
    void setupUi();
    void refreshList();

    hepatizon::core::VaultService& m_service;
    std::shared_ptr<hepatizon::core::UnlockedVault> m_vault;
    std::filesystem::path m_vaultPath;

    QLineEdit* m_searchBar{ nullptr };
    QListWidget* m_listWidget{ nullptr };
    QPushButton* m_btnAdd{ nullptr };
    QPushButton* m_btnSettings{ nullptr };
};

#endif // SRC_UI_GUI_VIEWS_DASHBOARDVIEW_HPP