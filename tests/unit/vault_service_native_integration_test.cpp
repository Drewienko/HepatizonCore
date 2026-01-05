#include "hepatizon/core/VaultHeaderAad.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include "test_utils/TestUtils.hpp"
#include "test_utils/VaultServiceScenarios.hpp"
#include <gtest/gtest.h>

TEST(VaultService, OpenReturnsNotFoundForMissingVault)
{
    auto crypto{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ *crypto, *storage };

    const auto dir{ hepatizon::test_utils::makeSecureTempDir("vault_service_missing_") };
    ASSERT_FALSE(dir.empty());

    const hepatizon::security::SecureString password{ hepatizon::security::secureStringFrom("x") };
    const auto res{ service.openVault(dir, password) };
    EXPECT_TRUE(std::holds_alternative<hepatizon::core::VaultError>(res));
    EXPECT_EQ(std::get<hepatizon::core::VaultError>(res), hepatizon::core::VaultError::NotFound);
}

TEST(VaultService, CreateUnlockAndSecretsWithNativeProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    const auto res{ hepatizon::test_utils::runVaultServiceCreateUnlockAndSecrets(*crypto, "vault_service_native_",
                                                                                 false) };
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, RejectsFutureSchemaWithNativeProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    const auto res{ hepatizon::test_utils::runVaultServiceRejectsFutureSchema(*crypto, "vault_service_native_",
                                                                              false) };
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, MigratesOldSchemaWithNativeProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    const auto res{ hepatizon::test_utils::runVaultServiceMigratesOldSchema(*crypto, "vault_service_native_", false) };
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, RekeyChangesPasswordWithoutReencryptingSecrets_NativeProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ *crypto, *storage };

    const auto dir{ hepatizon::test_utils::makeSecureTempDir("vault_service_rekey_native_") };
    ASSERT_FALSE(dir.empty());

    auto oldPassword{ hepatizon::security::secureStringFrom("old-password") };
    auto wipeOld{ hepatizon::security::scopeWipe(oldPassword) };
    const auto created{ service.createVault(dir, oldPassword) };
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::CreatedVault>(created));
    EXPECT_TRUE(service.vaultExists(dir));

    auto unlockedOrErr{ service.openVault(dir, oldPassword) };
    wipeOld.release();
    hepatizon::security::secureRelease(oldPassword);
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
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(openedNew));
    const auto& unlockedNew = std::get<hepatizon::core::UnlockedVault>(openedNew);

    const auto got{ service.getSecret(dir, unlockedNew, "k") };
    ASSERT_TRUE(std::holds_alternative<hepatizon::security::SecureString>(got));
    auto gotValue{ std::get<hepatizon::security::SecureString>(got) };
    const std::string_view gotView{ gotValue.data(), gotValue.size() };
    EXPECT_EQ(gotView, std::string_view{ "secret-value" });
    hepatizon::security::secureRelease(gotValue);
}

TEST(VaultService, MigratesV1HeaderToV2AndRekeysWithoutTouchingBlobs_NativeProvider)
{
    auto crypto{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ *crypto, *storage };

    const auto dir{ hepatizon::test_utils::makeSecureTempDir("vault_service_migrate_v1_rekey_native_") };
    ASSERT_FALSE(dir.empty());

    auto password{ hepatizon::security::secureStringFrom("password") };
    const auto created{ service.createVault(dir, password) };
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::CreatedVault>(created));

    auto unlockedOrErr{ service.openVault(dir, password) };
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(unlockedOrErr));
    auto unlocked0{ std::get<hepatizon::core::UnlockedVault>(std::move(unlockedOrErr)) };

    // Simulate a legacy (pre-DEK) vault:
    // - header payload is V1 (no stored secrets key),
    // - secrets are encrypted with a deterministic key derived from the password/master key.
    hepatizon::security::SecureBuffer masterKey{ crypto->deriveMasterKey(hepatizon::security::asBytes(password),
                                                                         unlocked0.kdf()) };
    constexpr std::string_view kSecretsKeyContext{ "hepatizon.vault.secrets.aead_key.v1" };
    hepatizon::security::SecureBuffer legacySecretsKey{ crypto->deriveSubkey(
        masterKey, std::as_bytes(std::span<const char>{ kSecretsKeyContext.data(), kSecretsKeyContext.size() }),
        hepatizon::crypto::g_aeadKeyBytes) };
    hepatizon::security::secureRelease(masterKey);

    auto plainText{ hepatizon::security::secureStringFrom("secret-value") };
    auto wipePlainText{ hepatizon::security::scopeWipe(plainText) };
    const auto keyChars{ std::span<const char>{ "k", 1 } };
    const auto aadForBlob{ std::as_bytes(keyChars) };
    const auto blobBox{ crypto->aeadEncrypt(legacySecretsKey, hepatizon::security::asBytes(plainText), aadForBlob) };
    storage->storeBlob(dir, "k", blobBox);
    wipePlainText.release();
    hepatizon::security::secureRelease(plainText);
    hepatizon::security::secureRelease(legacySecretsKey);

    const auto blobBefore{ storage->loadBlob(dir, "k") };
    ASSERT_TRUE(blobBefore.has_value());

    auto v1Header{ unlocked0.header() };
    v1Header.headerVersion = hepatizon::core::g_vaultHeaderVersionV1;
    const auto plainV1{ hepatizon::core::encodeVaultHeaderV1(v1Header) };
    const auto aad{ hepatizon::core::encodeVaultHeaderAadV1(unlocked0.kdf()) };
    const auto encryptedV1{ crypto->aeadEncrypt(unlocked0.headerKey(),
                                                std::span<const std::byte>{ plainV1.data(), plainV1.size() },
                                                std::span<const std::byte>{ aad.data(), aad.size() }) };
    storage->storeEncryptedHeader(dir, encryptedV1);

    auto password2{ hepatizon::security::secureStringFrom("password") };
    auto wipePassword2{ hepatizon::security::scopeWipe(password2) };
    auto unlockedAfterOrErr{ service.openVault(dir, password2) };
    wipePassword2.release();
    hepatizon::security::secureRelease(password2);
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(unlockedAfterOrErr));
    auto unlockedAfter{ std::get<hepatizon::core::UnlockedVault>(std::move(unlockedAfterOrErr)) };
    EXPECT_EQ(unlockedAfter.header().headerVersion, hepatizon::core::g_vaultHeaderVersionV2);

    const auto blobAfterMigration{ storage->loadBlob(dir, "k") };
    ASSERT_TRUE(blobAfterMigration.has_value());
    EXPECT_EQ(blobAfterMigration->nonce, blobBefore->nonce);
    EXPECT_EQ(blobAfterMigration->tag, blobBefore->tag);
    EXPECT_EQ(blobAfterMigration->cipherText, blobBefore->cipherText);

    auto newPassword{ hepatizon::security::secureStringFrom("new-password") };
    auto wipeNewPassword{ hepatizon::security::scopeWipe(newPassword) };
    const auto rekeyedOrErr{ service.rekeyVault(dir, std::move(unlockedAfter), newPassword) };
    wipeNewPassword.release();
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(rekeyedOrErr));

    const auto blobAfterRekey{ storage->loadBlob(dir, "k") };
    ASSERT_TRUE(blobAfterRekey.has_value());
    EXPECT_EQ(blobAfterRekey->nonce, blobBefore->nonce);
    EXPECT_EQ(blobAfterRekey->tag, blobBefore->tag);
    EXPECT_EQ(blobAfterRekey->cipherText, blobBefore->cipherText);

    const auto openedNew{ service.openVault(dir, newPassword) };
    hepatizon::security::secureRelease(newPassword);
    ASSERT_TRUE(std::holds_alternative<hepatizon::core::UnlockedVault>(openedNew));
    const auto& unlockedNew = std::get<hepatizon::core::UnlockedVault>(openedNew);

    const auto got{ service.getSecret(dir, unlockedNew, "k") };
    ASSERT_TRUE(std::holds_alternative<hepatizon::security::SecureString>(got));
    auto gotValue{ std::get<hepatizon::security::SecureString>(got) };
    const std::string_view gotView{ gotValue.data(), gotValue.size() };
    EXPECT_EQ(gotView, std::string_view{ "secret-value" });
    hepatizon::security::secureRelease(gotValue);

    hepatizon::security::secureRelease(password);
}
