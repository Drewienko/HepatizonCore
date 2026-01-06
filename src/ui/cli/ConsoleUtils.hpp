#ifndef HEPATIZON_UI_CLI_CONSOLEUTILS_HPP
#define HEPATIZON_UI_CLI_CONSOLEUTILS_HPP

#include "hepatizon/security/SecureString.hpp"
#include <string>

namespace hepatizon::ui::cli
{

void lockProcessMemory() noexcept;

[[nodiscard]] hepatizon::security::SecureString readPassword(const std::string& prompt);

} // namespace hepatizon::ui::cli

#endif // HEPATIZON_UI_CLI_CONSOLEUTILS_HPP