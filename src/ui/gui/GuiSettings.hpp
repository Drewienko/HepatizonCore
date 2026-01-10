#ifndef HEPATIZON_GUI_SETTINGS_HPP
#define HEPATIZON_GUI_SETTINGS_HPP

#include <QSettings>

namespace hepatizon::ui
{
constexpr int g_defaultSessionTimeoutSeconds = 300;
constexpr int g_defaultClipboardTimeoutMs = 15000;

inline int readSessionTimeoutSeconds()
{
    QSettings settings{};
    return settings.value("session/timeoutSeconds", g_defaultSessionTimeoutSeconds).toInt();
}

inline void writeSessionTimeoutSeconds(int seconds)
{
    QSettings settings{};
    settings.setValue("session/timeoutSeconds", seconds);
}

inline int readClipboardTimeoutMs()
{
    QSettings settings{};
    return settings.value("clipboard/timeoutMs", g_defaultClipboardTimeoutMs).toInt();
}

inline void writeClipboardTimeoutMs(int ms)
{
    QSettings settings{};
    settings.setValue("clipboard/timeoutMs", ms);
}
} // namespace hepatizon::ui

#endif // HEPATIZON_GUI_SETTINGS_HPP
