#ifndef SRC_UI_GUI_VIEWS_LOGINVIEW_HPP
#define SRC_UI_GUI_VIEWS_LOGINVIEW_HPP

#include "hepatizon/core/VaultService.hpp"
#include <QLineEdit>
#include <QPushButton>
#include <QWidget>
#include <filesystem>
#include <memory>

namespace hepatizon::core
{
class Session;
}

class LoginView : public QWidget
{
    Q_OBJECT
public:
    explicit LoginView(hepatizon::core::VaultService& service, QWidget* parent = nullptr);

signals:
    void vaultUnlocked(std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path);

private slots:
    void onBrowseClicked();
    void onUnlockClicked();
    void onCreateClicked();
    void togglePasswordVisibility();

private: // NOLINT(readability-redundant-access-specifiers)
    void setupUi();
    template <typename Func> bool processPasswordAndExecute(Func action);

    hepatizon::core::VaultService& m_service;

    QLineEdit* m_pathInput{ nullptr };
    QLineEdit* m_passInput{ nullptr };
    QPushButton* m_visibilityBtn{ nullptr };
};

#endif // SRC_UI_GUI_VIEWS_LOGINVIEW_HPP
