#ifndef HEPATIZON_SETTINGS_DIALOG_HPP
#define HEPATIZON_SETTINGS_DIALOG_HPP

#include "hepatizon/security/SecureString.hpp"
#include <QCheckBox>
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <optional>

class SettingsDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget* parent = nullptr);

    void setSessionTimeoutSeconds(int seconds);
    void setClipboardTimeoutMs(int ms);

    [[nodiscard]] int sessionTimeoutSeconds() const noexcept;
    [[nodiscard]] int clipboardTimeoutMs() const noexcept;

    [[nodiscard]] std::optional<hepatizon::security::SecureString> takeNewPassword() noexcept;

private slots:
    void onDisableTimeoutToggled(bool checked);
    void onSaveClicked();

private:
    void setupUi();
    void clearPasswordFields();

    QCheckBox* m_disableTimeout{ nullptr };
    QSpinBox* m_timeoutMinutes{ nullptr };
    QSpinBox* m_clipboardSeconds{ nullptr };
    QLineEdit* m_newPassword{ nullptr };
    QLineEdit* m_confirmPassword{ nullptr };
    QPushButton* m_saveButton{ nullptr };
    QPushButton* m_cancelButton{ nullptr };

    std::optional<hepatizon::security::SecureString> m_pendingPassword{};
};

#endif // HEPATIZON_SETTINGS_DIALOG_HPP
