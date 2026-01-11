#ifndef SRC_UI_GUI_VIEWS_DASHBOARDVIEW_HPP
#define SRC_UI_GUI_VIEWS_DASHBOARDVIEW_HPP

#include "hepatizon/core/Session.hpp"
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

    void loadVault(std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path);

signals:
    void secretClicked(const std::string& key);
    void addClicked();
    void settingsClicked();
    void lockClicked();

private slots:
    void onSearchChanged(const QString& text);
    void onItemClicked(QListWidgetItem* item);
    void onDeleteClicked();

private: // NOLINT(readability-redundant-access-specifiers)
    void setupUi();
    void refreshList();

    hepatizon::core::VaultService& m_service;
    std::shared_ptr<hepatizon::core::Session> m_session;
    std::filesystem::path m_vaultPath;

    QLineEdit* m_searchBar{ nullptr };
    QListWidget* m_listWidget{ nullptr };
    QPushButton* m_btnAdd{ nullptr };
    QPushButton* m_btnSettings{ nullptr };
    QPushButton* m_btnLock{ nullptr };
    QPushButton* m_btnDelete{ nullptr };
};

#endif // SRC_UI_GUI_VIEWS_DASHBOARDVIEW_HPP
