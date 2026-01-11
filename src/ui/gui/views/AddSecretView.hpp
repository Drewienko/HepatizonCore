#ifndef SRC_UI_GUI_VIEWS_ADDSECRETVIEW_HPP
#define SRC_UI_GUI_VIEWS_ADDSECRETVIEW_HPP

#include "hepatizon/core/Session.hpp"
#include "hepatizon/core/VaultService.hpp"
#include <QLineEdit>
#include <QPushButton>
#include <QWidget>
#include <memory>

class AddSecretView : public QWidget
{
    Q_OBJECT
public:
    explicit AddSecretView(hepatizon::core::VaultService& service, QWidget* parent = nullptr);

    void resetFields();
    void setVaultContext(std::shared_ptr<hepatizon::core::Session> session, std::filesystem::path path);

signals:
    void cancelClicked();
    void secretSaved();

private slots:
    void onSaveClicked();
    void onGenerateClicked();

private: // NOLINT(readability-redundant-access-specifiers)
    void setupUi();

    hepatizon::core::VaultService& m_service;
    std::shared_ptr<hepatizon::core::Session> m_session;
    std::filesystem::path m_vaultPath;

    QLineEdit* m_keyInput{ nullptr };
    QLineEdit* m_valueInput{ nullptr };
    QPushButton* m_btnSave{ nullptr };
    QPushButton* m_btnCancel{ nullptr };
};

#endif // SRC_UI_GUI_VIEWS_ADDSECRETVIEW_HPP
