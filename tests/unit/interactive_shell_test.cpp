#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "InteractiveShell.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

#include <filesystem>
#include <random>
#include <sstream>

namespace fs = std::filesystem;

class InteractiveShellTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        std::random_device rd;
        std::mt19937 gen(rd());

        constexpr int kMinId = 1000;
        constexpr int kMaxId = 9999;
        std::uniform_int_distribution<> distrib(kMinId, kMaxId);

        m_testDir = fs::temp_directory_path() / ("hepc_shell_test_" + std::to_string(distrib(gen)));

        if (fs::exists(m_testDir))
        {
            fs::remove_all(m_testDir);
        }
        fs::create_directories(m_testDir);

        m_crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
        m_storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
        m_service = std::make_unique<hepatizon::core::VaultService>(*m_crypto, *m_storage);
    }

    void TearDown() override
    {
        m_service.reset();
        m_storage.reset();
        m_crypto.reset();

        if (fs::exists(m_testDir))
        {
            std::error_code ec;
            fs::remove_all(m_testDir, ec);
        }
    }

    fs::path m_testDir;                                                // NOLINT
    std::unique_ptr<hepatizon::crypto::ICryptoProvider> m_crypto;      // NOLINT
    std::unique_ptr<hepatizon::storage::IStorageRepository> m_storage; // NOLINT
    std::unique_ptr<hepatizon::core::VaultService> m_service;          // NOLINT

    std::stringstream m_inContent;  // NOLINT
    std::stringstream m_outContent; // NOLINT
};

TEST_F(InteractiveShellTest, CompleteSessionFlow)
{
    fs::path vaultPath = m_testDir / "my_vault";

    m_inContent << "create " << vaultPath.string() << "\n";
    m_inContent << "put my_key\n";
    m_inContent << "get my_key\n";
    m_inContent << "ls\n";
    m_inContent << "close\n";
    m_inContent << "exit\n";

    auto mockReader = [&](const std::string& prompt) -> hepatizon::security::SecureString
    {
        if (prompt.find("Secret Value") != std::string::npos)
        {
            return hepatizon::security::secureStringFrom("secret_data");
        }
        return hepatizon::security::secureStringFrom("pass123");
    };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, mockReader);
    shell.run();

    std::string output = m_outContent.str();

    if (output.find("Vault created.") == std::string::npos)
    {
        std::cerr << "TEST FAILURE DEBUG OUTPUT:\n" << output << std::endl;
    }

    EXPECT_THAT(output, ::testing::HasSubstr("Vault created."));
    EXPECT_THAT(output, ::testing::HasSubstr("Vault opened."));
    EXPECT_THAT(output, ::testing::HasSubstr("Secret stored."));
    EXPECT_THAT(output, ::testing::HasSubstr("secret_data"));
    EXPECT_THAT(output, ::testing::HasSubstr("- my_key"));
    EXPECT_THAT(output, ::testing::HasSubstr("Vault closed."));
}

TEST_F(InteractiveShellTest, CreateFailsOnPasswordMismatch)
{
    fs::path vaultPath = m_testDir / "mismatch_vault";
    m_inContent << "create " << vaultPath.string() << "\n";
    m_inContent << "exit\n";

    int callCount = 0;
    auto mismatchReader = [&](const std::string&)
    {
        callCount++;
        return (callCount == 1) ? hepatizon::security::secureStringFrom("passA")
                                : hepatizon::security::secureStringFrom("passB");
    };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, mismatchReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Error: Passwords do not match."));
    EXPECT_FALSE(fs::exists(vaultPath));
}

TEST_F(InteractiveShellTest, CreateFailsIfVaultAlreadyExists)
{
    fs::path vaultPath = m_testDir / "existing_vault";

    auto p1 = hepatizon::security::secureStringFrom("pass");
    auto res = m_service->createVault(vaultPath, p1);

    if (std::holds_alternative<hepatizon::core::VaultError>(res))
    {
        auto err = std::get<hepatizon::core::VaultError>(res);
        FAIL() << "Setup failed: Could not create initial vault. Error code: " << static_cast<int>(err);
    }

    m_inContent << "create " << vaultPath.string() << "\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::secureStringFrom("pass"); };
    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Error: Vault already exists"));
}

TEST_F(InteractiveShellTest, OpenFailsOnWrongPassword)
{
    fs::path vaultPath = m_testDir / "auth_vault";
    {
        auto p1 = hepatizon::security::secureStringFrom("correct_pass");
        auto res = m_service->createVault(vaultPath, p1);
        if (std::holds_alternative<hepatizon::core::VaultError>(res))
        {
            auto err = std::get<hepatizon::core::VaultError>(res);
            // FIX: Używamy static_cast, bo err to enum class
            FAIL() << "Setup failed: Could not create initial vault. Error code: " << static_cast<int>(err);
        }
    }

    m_inContent << "open " << vaultPath.string() << "\n";
    m_inContent << "exit\n";

    auto badPassReader = [](const std::string&) { return hepatizon::security::secureStringFrom("WRONG_PASS"); };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, badPassReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Error: Authentication failed"));
}

TEST_F(InteractiveShellTest, OpenFailsOnMissingDirectory)
{
    m_inContent << "open " << (m_testDir / "non_existent").string() << "\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };
    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Error: Vault does not exist"));
}

TEST_F(InteractiveShellTest, CloseFailsIfNoVaultOpen)
{
    m_inContent << "close\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };
    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Error: No vault open"));
}

TEST_F(InteractiveShellTest, OperationFailsIfVaultLocked)
{
    m_inContent << "put k\n";
    m_inContent << "get k\n";
    m_inContent << "rm k\n";
    m_inContent << "ls\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };
    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    std::string output = m_outContent.str();
    int count = 0;
    size_t pos = 0;
    std::string errorMsg = "Error: Vault is locked.";
    while ((pos = output.find(errorMsg, pos)) != std::string::npos)
    {
        count++;
        pos += errorMsg.length();
    }
    EXPECT_GE(count, 4);
}

TEST_F(InteractiveShellTest, HelpCommandWorks)
{
    m_inContent << "help\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };
    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    std::string output = m_outContent.str();
    EXPECT_THAT(output, ::testing::HasSubstr("SUBCOMMANDS:"));
    EXPECT_THAT(output, ::testing::HasSubstr("open"));
    EXPECT_THAT(output, ::testing::HasSubstr("create"));
}

TEST_F(InteractiveShellTest, SyntaxErrorOnBadArguments)
{
    m_inContent << "create\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };
    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Syntax Error"));
}

TEST_F(InteractiveShellTest, HandlesQuotedArguments)
{
    fs::path vaultPath = m_testDir / "vault with spaces";
    std::string vaultPathStr = vaultPath.string();

    m_inContent << "create \"" << vaultPathStr << "\"\n";
    m_inContent << "exit\n";

    auto mockReader = [&](const std::string&) { return hepatizon::security::secureStringFrom("pass"); };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, mockReader);
    int exitCode = shell.run();

    EXPECT_EQ(exitCode, 0);
    EXPECT_TRUE(fs::exists(vaultPath));
    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Vault created."));
}

TEST_F(InteractiveShellTest, FailsOnUnclosedQuotes)
{
    m_inContent << "create \"unclosed_quote_path\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    EXPECT_THAT(m_outContent.str(), ::testing::HasSubstr("Error: Create failed."));
}

TEST_F(InteractiveShellTest, EnforcesArgumentCounts)
{
    m_inContent << "create\n";
    m_inContent << "open\n";
    m_inContent << "create arg1 arg2\n";
    m_inContent << "put\n";
    m_inContent << "get\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    std::string output = m_outContent.str();

    EXPECT_THAT(output, ::testing::HasSubstr("Error"));
    EXPECT_THAT(output, ::testing::Not(::testing::HasSubstr("Vault created.")));
}

TEST_F(InteractiveShellTest, RequiresOpenVaultForOperations)
{
    m_inContent << "put my_secret\n";
    m_inContent << "get my_secret\n";
    m_inContent << "ls\n";
    m_inContent << "exit\n";

    auto dummyReader = [](const std::string&) { return hepatizon::security::SecureString{}; };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, dummyReader);
    shell.run();

    std::string output = m_outContent.str();
    EXPECT_THAT(output, ::testing::HasSubstr("Vault is locked."));
}

TEST_F(InteractiveShellTest, IgnoresExcessiveWhitespace)
{
    fs::path vaultPath = m_testDir / "whitespace_vault";

    m_inContent << "   create    " << vaultPath.string() << "   \n";
    m_inContent << "\t exit \t \n";

    auto mockReader = [&](const std::string&) { return hepatizon::security::secureStringFrom("pass"); };

    hepatizon::ui::cli::InteractiveShell shell(*m_service, m_inContent, m_outContent, mockReader);
    int exitCode = shell.run();

    EXPECT_EQ(exitCode, 0);
    EXPECT_TRUE(fs::exists(vaultPath));
}