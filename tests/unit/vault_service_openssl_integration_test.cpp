#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include "test_utils/TestUtils.hpp"
#include "test_utils/VaultServiceScenarios.hpp"
#include <gtest/gtest.h>

namespace
{

void maybeSkip(const hepatizon::test_utils::ScenarioResult& res)
{
    if (res.outcome == hepatizon::test_utils::ScenarioOutcome::Skip)
    {
        GTEST_SKIP() << res.skipReason;
    }
}

} // namespace

TEST(VaultService, CreateUnlockAndSecretsWithOpenSslProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeOpenSslCryptoProvider() };
    const auto res{ hepatizon::test_utils::runVaultServiceCreateUnlockAndSecrets(*crypto, "vault_service_openssl_",
                                                                                 true) };
    maybeSkip(res);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, RejectsFutureSchemaWithOpenSslProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeOpenSslCryptoProvider() };
    const auto res{ hepatizon::test_utils::runVaultServiceRejectsFutureSchema(*crypto, "vault_service_openssl_",
                                                                              true) };
    maybeSkip(res);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, MigratesOldSchemaWithOpenSslProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeOpenSslCryptoProvider() };
    const auto res{ hepatizon::test_utils::runVaultServiceMigratesOldSchema(*crypto, "vault_service_openssl_", true) };
    maybeSkip(res);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, RekeyChangesPasswordWithoutReencryptingSecrets_OpenSslProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeOpenSslCryptoProvider() };
    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ *crypto, *storage };

    const auto dir{ hepatizon::test_utils::makeSecureTempDir("vault_service_rekey_openssl_") };
    ASSERT_FALSE(dir.empty());

    auto oldPassword{ hepatizon::security::secureStringFrom("old-password") };
    auto wipeOld{ hepatizon::security::scopeWipe(oldPassword) };
    const auto created{ service.createVault(dir, oldPassword) };
    if (std::holds_alternative<hepatizon::core::VaultError>(created) &&
        std::get<hepatizon::core::VaultError>(created) == hepatizon::core::VaultError::UnsupportedKdfMetadata)
    {
        GTEST_SKIP() << "OpenSSL provider does not support required KDF/MACs in this environment";
    }
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::CreatedVault>(created));

    auto unlockedOrErr{ service.openVault(dir, oldPassword) };
    wipeOld.release();
    hepatizon::security::secureRelease(oldPassword);
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockedOrErr) &&
        std::get<hepatizon::core::VaultError>(unlockedOrErr) == hepatizon::core::VaultError::UnsupportedKdfMetadata)
    {
        GTEST_SKIP() << "OpenSSL provider does not support required KDF/MACs in this environment";
    }
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(unlockedOrErr));
    auto unlocked{ std::get<hepatizon::core::UnlockedVault>(std::move(unlockedOrErr)) };

    auto value{ hepatizon::security::secureStringFrom("secret-value") };
    auto wipeValue{ hepatizon::security::scopeWipe(value) };
    const auto putRes{ service.putSecret(dir, unlocked, "k", value) };
    wipeValue.release();
    hepatizon::security::secureRelease(value);
    ASSERT_TRUE(std::holds_alternative<std::monostate>(putRes));

    auto newPassword{ hepatizon::security::secureStringFrom("new-password") };
    auto wipeNew{ hepatizon::security::scopeWipe(newPassword) };
    const auto rekeyedOrErr{ service.rekeyVault(dir, std::move(unlocked), newPassword) };
    if (std::holds_alternative<hepatizon::core::VaultError>(rekeyedOrErr) &&
        std::get<hepatizon::core::VaultError>(rekeyedOrErr) == hepatizon::core::VaultError::UnsupportedKdfMetadata)
    {
        wipeNew.release();
        hepatizon::security::secureRelease(newPassword);
        GTEST_SKIP() << "OpenSSL provider does not support required KDF/MACs in this environment";
    }
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(rekeyedOrErr));

    auto oldPassword2{ hepatizon::security::secureStringFrom("old-password") };
    auto wipeOld2{ hepatizon::security::scopeWipe(oldPassword2) };
    const auto openWithOld{ service.openVault(dir, oldPassword2) };
    wipeOld2.release();
    hepatizon::security::secureRelease(oldPassword2);
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(openWithOld));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(openWithOld), hepatizon::core::VaultError::AuthFailed);

    const auto openedNew{ service.openVault(dir, newPassword) };
    wipeNew.release();
    hepatizon::security::secureRelease(newPassword);
    if (std::holds_alternative<hepatizon::core::VaultError>(openedNew) &&
        std::get<hepatizon::core::VaultError>(openedNew) == hepatizon::core::VaultError::UnsupportedKdfMetadata)
    {
        GTEST_SKIP() << "OpenSSL provider does not support required KDF/MACs in this environment";
    }
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(openedNew));
    const auto& unlockedNew = std::get<hepatizon::core::UnlockedVault>(openedNew);

    const auto got{ service.getSecret(dir, unlockedNew, "k") };
    ASSERT_TRUE(std::holds_alternative<hepatizon::security::SecureString>(got));
    auto gotValue{ std::get<hepatizon::security::SecureString>(got) };
    const std::string_view gotView{ gotValue.data(), gotValue.size() };
    EXPECT_EQ(gotView, std::string_view{ "secret-value" });
    hepatizon::security::secureRelease(gotValue);
}
