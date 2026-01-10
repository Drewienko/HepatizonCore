#ifndef SRC_UI_GUI_COMPONENTS_SECRETDIALOG_HPP
#define SRC_UI_GUI_COMPONENTS_SECRETDIALOG_HPP

#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTimer>

class SecretDialog final : public QDialog
{
    Q_OBJECT
public:
    explicit SecretDialog(QWidget* parent = nullptr);

    void setSecret(const QString& key, const QString& value);
    void setClipboardTimeoutMs(int timeoutMs) noexcept;

private slots:
    void onCopyClicked();
    void onToggleReveal(bool checked);
    void clearClipboardIfUnchanged();

private:
    void clearSensitiveFields();

    QLabel* m_keyLabel{ nullptr };
    QLineEdit* m_valueInput{ nullptr };
    QPushButton* m_copyBtn{ nullptr };
    QPushButton* m_revealBtn{ nullptr };
    QPushButton* m_closeBtn{ nullptr };
    QTimer* m_clipboardTimer{ nullptr };
    int m_copyTimeoutMs{ 0 };
};

#endif // SRC_UI_GUI_COMPONENTS_SECRETDIALOG_HPP
