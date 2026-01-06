#ifndef HEPATIZON_UI_CLI_INTERACTIVESHELL_HPP
#define HEPATIZON_UI_CLI_INTERACTIVESHELL_HPP

#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/security/SecureString.hpp"

#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <string>

namespace hepatizon::ui::cli
{

// In tests: returns a pre-determined string.
using PasswordReader = std::function<hepatizon::security::SecureString(const std::string&)>;

class InteractiveShell final
{
public:
    InteractiveShell(hepatizon::core::VaultService& service, std::istream& in, std::ostream& out,
                     PasswordReader pwdReader);

    int run();

private:
    hepatizon::core::VaultService& m_service;
    std::istream& m_in;
    std::ostream& m_out;
    PasswordReader m_pwdReader;

    std::optional<hepatizon::core::UnlockedVault> m_vault;
    std::filesystem::path m_currentPath;
    bool m_running{ true };

    void processLine(const std::string& line);

    void doOpen(const std::string& path);
    void doCreate(const std::string& path);
    void doClose();
    void doList();
    void doPut(const std::string& key);
    void doGet(const std::string& key);
    void doRm(const std::string& key);
};

} // namespace hepatizon::ui::cli

#endif // HEPATIZON_UI_CLI_INTERACTIVESHELL_HPP