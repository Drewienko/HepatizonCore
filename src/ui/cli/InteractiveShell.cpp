#include "InteractiveShell.hpp"
#include "Tokenizer.hpp"
#include "hepatizon/security/ScopeWipe.hpp"

#include <CLI/CLI.hpp>
#include <vector>

namespace hepatizon::ui::cli
{

InteractiveShell::InteractiveShell(hepatizon::core::VaultService& service, std::istream& in, std::ostream& out,
                                   PasswordReader pwdReader)
    : m_service(service), m_in(in), m_out(out), m_pwdReader(std::move(pwdReader))
{
}

int InteractiveShell::run()
{
    m_out << "HepatizonCore SafeShell (CLI11 Powered)\n";
    m_out << "Type 'help' for available commands.\n";

    std::string line;
    while (m_running && m_in.good())
    {
        if (m_vault.has_value())
        {
            m_out << "hepc(" << m_currentPath.filename().string() << ")> ";
        }
        else
        {
            m_out << "hepc> ";
        }

        if (!std::getline(m_in, line))
        {
            break; // EOF
        }

        if (line.empty())
        {
            continue;
        }

        processLine(line);
    }
    return 0;
}

void InteractiveShell::processLine(const std::string& line)
{
    std::vector<std::string> userArgs = Tokenizer::tokenize(line);

    if (userArgs.empty())
    {
        return;
    }

    // UX FIX: Treat 'help' command exactly like '--help' flag.
    // This forces CLI11 to display the ROOT help message instead of context-sensitive help for the 'help' subcommand.
    if (userArgs[0] == "help")
    {
        userArgs[0] = "--help";
    }

    std::vector<std::string> args;
    args.reserve(userArgs.size() + 1);
    args.emplace_back("hepc");
    args.insert(args.end(), userArgs.begin(), userArgs.end());

    CLI::App app{ "Hepatizon Shell" };
    app.require_subcommand(1);

    // HELP (Registered so it appears in the list, but 'hepc help' input is intercepted above)
    app.add_subcommand("help", "Print this help message")->callback([]() { throw CLI::CallForHelp(); });

    // EXIT / QUIT
    app.add_subcommand("exit", "Exit the shell")->alias("quit")->callback([this]() { m_running = false; });

    // OPEN
    std::string pathArg;
    auto* subOpen = app.add_subcommand("open", "Open an existing vault");
    subOpen->add_option("path", pathArg, "Path to vault directory")->required();
    subOpen->callback([&]() { doOpen(pathArg); });

    // CREATE
    auto* subCreate = app.add_subcommand("create", "Create a new vault");
    subCreate->add_option("path", pathArg, "Path to new vault")->required();
    subCreate->callback([&]() { doCreate(pathArg); });

    // CLOSE
    app.add_subcommand("close", "Close current vault")->callback([this]() { doClose(); });

    // LS
    app.add_subcommand("ls", "List secret keys")->callback([this]() { doList(); });

    // PUT
    std::string keyArg;
    auto* subPut = app.add_subcommand("put", "Store a secret (prompts for value)");
    subPut->add_option("key", keyArg, "Secret key identifier")->required();
    subPut->callback([&]() { doPut(keyArg); });

    // GET
    auto* subGet = app.add_subcommand("get", "Retrieve a secret value");
    subGet->add_option("key", keyArg, "Secret key identifier")->required();
    subGet->callback([&]() { doGet(keyArg); });

    // RM
    auto* subRm = app.add_subcommand("rm", "Delete a secret");
    subRm->add_option("key", keyArg, "Secret key identifier")->required();
    subRm->callback([&]() { doRm(keyArg); });

    // --- Parsing Execution ---
    try
    {
        std::vector<char*> argv;
        argv.reserve(args.size());
        for (const auto& arg : args)
        {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }

        app.parse(static_cast<int>(argv.size()), argv.data());
    }
    catch ([[maybe_unused]] const CLI::CallForHelp&)
    {
        m_out << app.help();
    }
    catch (const CLI::ParseError& e)
    {
        m_out << "Syntax Error: " << e.what() << "\n";
    }
}

// --- Handlers ---

void InteractiveShell::doOpen(const std::string& path)
{
    if (!m_service.vaultExists(path))
    {
        m_out << "Error: Vault does not exist at " << path << "\n";
        return;
    }

    auto pass = m_pwdReader("Password: ");
    auto wipePass = hepatizon::security::scopeWipe(pass);

    auto result = m_service.openVault(path, pass);
    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        m_out << "Error: Authentication failed or invalid vault.\n";
    }
    else
    {
        m_vault = std::move(std::get<hepatizon::core::UnlockedVault>(result));
        m_currentPath = path;
        m_out << "Vault opened.\n";
    }
}

void InteractiveShell::doCreate(const std::string& path)
{
    if (m_service.vaultExists(path))
    {
        m_out << "Error: Vault already exists at " << path << "\n";
        return;
    }

    auto p1 = m_pwdReader("New Password: ");
    auto wipeP1 = hepatizon::security::scopeWipe(p1);

    auto p2 = m_pwdReader("Confirm Password: ");
    auto wipeP2 = hepatizon::security::scopeWipe(p2);

    if (hepatizon::security::asStringView(p1) != hepatizon::security::asStringView(p2))
    {
        m_out << "Error: Passwords do not match.\n";
        return;
    }

    auto result = m_service.createVault(path, p1);
    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        m_out << "Error: Create failed.\n";
    }
    else
    {
        m_out << "Vault created.\n";
        doOpen(path);
    }
}

void InteractiveShell::doClose()
{
    if (!m_vault.has_value())
    {
        m_out << "Error: No vault open.\n";
        return;
    }
    m_vault.reset();
    m_currentPath.clear();
    m_out << "Vault closed.\n";
}

void InteractiveShell::doList()
{
    if (!m_vault.has_value())
    {
        m_out << "Error: Vault is locked.\n";
        return;
    }

    auto result = m_service.listSecretKeys(m_currentPath, *m_vault);
    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        m_out << "Error: Failed to list keys.\n";
        return;
    }

    const auto& keys = std::get<std::vector<std::string>>(result);
    if (keys.empty())
    {
        m_out << "(empty)\n";
    }
    else
    {
        for (const auto& k : keys)
        {
            m_out << " - " << k << "\n";
        }
    }
}

void InteractiveShell::doPut(const std::string& key)
{
    if (!m_vault.has_value())
    {
        m_out << "Error: Vault is locked.\n";
        return;
    }

    auto val = m_pwdReader("Secret Value: ");
    auto wipeVal = hepatizon::security::scopeWipe(val);

    auto result = m_service.putSecret(m_currentPath, *m_vault, key, val);
    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        m_out << "Error: Failed to write secret.\n";
    }
    else
    {
        m_out << "Secret stored.\n";
    }
}

void InteractiveShell::doGet(const std::string& key)
{
    if (!m_vault.has_value())
    {
        m_out << "Error: Vault is locked.\n";
        return;
    }

    auto result = m_service.getSecret(m_currentPath, *m_vault, key);
    if (auto* sec = std::get_if<hepatizon::security::SecureString>(&result))
    {
        auto wipeSec = hepatizon::security::scopeWipe(*sec);
        m_out << hepatizon::security::asStringView(*sec) << "\n";
    }
    else
    {
        m_out << "Error: Secret not found.\n";
    }
}

void InteractiveShell::doRm(const std::string& key)
{
    if (!m_vault.has_value())
    {
        m_out << "Error: Vault is locked.\n";
        return;
    }

    auto result = m_service.deleteSecret(m_currentPath, *m_vault, key);
    if (std::holds_alternative<hepatizon::core::VaultError>(result))
    {
        if (std::get<hepatizon::core::VaultError>(result) == hepatizon::core::VaultError::NotFound)
        {
            m_out << "Error: Secret not found.\n";
        }
        else
        {
            m_out << "Error: Failed to delete secret.\n";
        }
    }
    else
    {
        m_out << "Secret deleted (if it existed).\n";
    }
}

} // namespace hepatizon::ui::cli