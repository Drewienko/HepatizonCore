#ifndef HEPATIZON_TESTS_TEST_UTILS_VAULTSERVICESCENARIOS_HPP
#define HEPATIZON_TESTS_TEST_UTILS_VAULTSERVICESCENARIOS_HPP

#include "hepatizon/core/VaultHeaderAad.hpp"
#include "hepatizon/core/KdfPolicy.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include "test_utils/TestUtils.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string_view>
#include <variant>

namespace hepatizon::test_utils
{

enum class ScenarioOutcome : std::uint8_t
{
    Ok,
    Skip,
    Failed,
};

struct ScenarioResult final
{
    ScenarioOutcome outcome{ ScenarioOutcome::Failed };
    std::string_view skipReason{};
};

[[nodiscard]] inline hepatizon::crypto::Argon2idParams argon2idParamsForVaultTests() noexcept
{
    if (std::getenv("HEPC_RUN_SLOW_TESTS") != nullptr)
    {
        return hepatizon::core::defaultArgon2idParams();
    }

    constexpr std::uint32_t kFastIterations{ 1U };
    constexpr std::uint32_t kFastMemoryKiB{ 8U };
    constexpr std::uint32_t kFastParallelism{ 1U };
    return hepatizon::crypto::Argon2idParams{
        .iterations = kFastIterations,
        .memoryKiB = kFastMemoryKiB,
        .parallelism = kFastParallelism,
    };
}

[[nodiscard]] inline ScenarioResult runVaultServiceCreateUnlockAndSecrets(hepatizon::crypto::ICryptoProvider& crypto,
                                                                         std::string_view tempPrefix,
                                                                         bool allowSkipUnsupportedKdf) noexcept
{
    const auto dir = hepatizon::test_utils::makeSecureTempDir(tempPrefix);
    if (dir.empty())
    {
        ADD_FAILURE() << "failed to create temp dir";
        return { ScenarioOutcome::Failed, {} };
    }

    auto storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
    hepatizon::core::VaultService service{ crypto, *storage };

    auto password = hepatizon::security::secureStringFrom("correct horse battery staple");
    auto wipePassword = hepatizon::security::scopeWipe(password);

    const auto createRes = service.createVault(dir, hepatizon::security::asBytes(password), argon2idParamsForVaultTests());
    if (std::holds_alternative<hepatizon::core::VaultError>(createRes))
    {
        const auto err = std::get<hepatizon::core::VaultError>(createRes);
        if (allowSkipUnsupportedKdf && err == hepatizon::core::VaultError::UnsupportedKdfMetadata)
        {
            wipePassword.release();
            hepatizon::security::secureRelease(password);
            std::filesystem::remove_all(dir);
            return { ScenarioOutcome::Skip, "provider does not support Argon2id KDF at runtime" };
        }
        ADD_FAILURE() << "createVault failed: " << static_cast<int>(err);
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    const auto created = std::get<hepatizon::core::CreatedVault>(createRes);

    auto unlockRes = service.unlockVault(dir, hepatizon::security::asBytes(password));
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockRes))
    {
        ADD_FAILURE() << "unlockVault failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    auto unlocked = std::move(std::get<hepatizon::core::UnlockedVault>(unlockRes));

    // AEAD authentication should fail if AAD does not match (empty AAD here).
    try
    {
        const auto storedInfo = storage->loadVaultInfo(dir);
        const auto wrongAad = crypto.aeadDecrypt(unlocked.masterKey(), storedInfo.encryptedHeader, {});
        if (wrongAad.has_value())
        {
            ADD_FAILURE() << "decrypting with wrong AAD unexpectedly succeeded";
            wipePassword.release();
            hepatizon::security::secureRelease(password);
            std::filesystem::remove_all(dir);
            return { ScenarioOutcome::Failed, {} };
        }
    }
    catch (...)
    {
        ADD_FAILURE() << "storage read/decrypt threw during wrong-AAD check";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    if (unlocked.kdf().policyVersion != created.kdf().policyVersion ||
        static_cast<std::uint32_t>(unlocked.kdf().algorithm) != static_cast<std::uint32_t>(created.kdf().algorithm) ||
        unlocked.kdf().argon2Version != created.kdf().argon2Version ||
        unlocked.kdf().derivedKeyBytes != created.kdf().derivedKeyBytes ||
        unlocked.kdf().argon2id.iterations != created.kdf().argon2id.iterations ||
        unlocked.kdf().argon2id.memoryKiB != created.kdf().argon2id.memoryKiB ||
        unlocked.kdf().argon2id.parallelism != created.kdf().argon2id.parallelism || unlocked.kdf().salt != created.kdf().salt)
    {
        ADD_FAILURE() << "KdfMetadata mismatch after unlock";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    if (unlocked.header().headerVersion != hepatizon::core::g_vaultHeaderVersionV1 ||
        unlocked.header().vaultId != created.header().vaultId ||
        unlocked.header().createdAtUnixSeconds != created.header().createdAtUnixSeconds ||
        unlocked.header().dbSchemaVersion != hepatizon::core::g_vaultDbSchemaVersionCurrent || unlocked.header().flags != 0U)
    {
        ADD_FAILURE() << "VaultHeader mismatch after unlock";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    if (unlocked.masterKey().empty())
    {
        ADD_FAILURE() << "master key is empty";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    constexpr std::string_view kKey{ "demo.secret" };
    constexpr std::string_view kValue{ "demo value" };

    auto value = hepatizon::security::secureStringFrom(kValue);
    auto wipeValue = hepatizon::security::scopeWipe(value);
    const auto putRes = service.putSecret(dir, unlocked, kKey, value);
    wipeValue.release();
    hepatizon::security::secureRelease(value);
    if (!std::holds_alternative<std::monostate>(putRes))
    {
        ADD_FAILURE() << "putSecret failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    auto getRes = service.getSecret(dir, unlocked, kKey);
    if (!std::holds_alternative<hepatizon::security::SecureString>(getRes))
    {
        ADD_FAILURE() << "getSecret failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    auto loaded = std::get<hepatizon::security::SecureString>(getRes);
    auto wipeLoaded = hepatizon::security::scopeWipe(loaded);
    if (hepatizon::security::asStringView(loaded) != kValue)
    {
        ADD_FAILURE() << "secret value mismatch";
        wipeLoaded.release();
        hepatizon::security::secureRelease(loaded);
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    wipeLoaded.release();
    hepatizon::security::secureRelease(loaded);

    const auto missingRes = service.getSecret(dir, unlocked, "missing.key");
    if (!std::holds_alternative<hepatizon::core::VaultError>(missingRes) ||
        std::get<hepatizon::core::VaultError>(missingRes) != hepatizon::core::VaultError::NotFound)
    {
        ADD_FAILURE() << "missing key did not return NotFound";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    // Wrong password should fail authentication (but not crash).
    auto wrongPassword = hepatizon::security::secureStringFrom("wrong password");
    auto wipeWrongPassword = hepatizon::security::scopeWipe(wrongPassword);
    const auto wrongUnlock = service.unlockVault(dir, hepatizon::security::asBytes(wrongPassword));
    wipeWrongPassword.release();
    hepatizon::security::secureRelease(wrongPassword);
    if (!std::holds_alternative<hepatizon::core::VaultError>(wrongUnlock) ||
        std::get<hepatizon::core::VaultError>(wrongUnlock) != hepatizon::core::VaultError::AuthFailed)
    {
        ADD_FAILURE() << "wrong password did not return AuthFailed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    wipePassword.release();
    hepatizon::security::secureRelease(password);
    std::filesystem::remove_all(dir);
    return { ScenarioOutcome::Ok, {} };
}

[[nodiscard]] inline ScenarioResult runVaultServiceRejectsFutureSchema(hepatizon::crypto::ICryptoProvider& crypto,
                                                                      std::string_view tempPrefix,
                                                                      bool allowSkipUnsupportedKdf) noexcept
{
    const auto dir = hepatizon::test_utils::makeSecureTempDir(tempPrefix);
    if (dir.empty())
    {
        ADD_FAILURE() << "failed to create temp dir";
        return { ScenarioOutcome::Failed, {} };
    }

    auto storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
    hepatizon::core::VaultService service{ crypto, *storage };

    auto password = hepatizon::security::secureStringFrom("correct horse battery staple");
    auto wipePassword = hepatizon::security::scopeWipe(password);

    const auto createRes = service.createVault(dir, hepatizon::security::asBytes(password), argon2idParamsForVaultTests());
    if (std::holds_alternative<hepatizon::core::VaultError>(createRes))
    {
        const auto err = std::get<hepatizon::core::VaultError>(createRes);
        if (allowSkipUnsupportedKdf && err == hepatizon::core::VaultError::UnsupportedKdfMetadata)
        {
            wipePassword.release();
            hepatizon::security::secureRelease(password);
            std::filesystem::remove_all(dir);
            return { ScenarioOutcome::Skip, "provider does not support Argon2id KDF at runtime" };
        }
        ADD_FAILURE() << "createVault failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    auto unlockRes = service.unlockVault(dir, hepatizon::security::asBytes(password));
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockRes))
    {
        ADD_FAILURE() << "unlockVault failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    const auto& unlocked = std::get<hepatizon::core::UnlockedVault>(unlockRes);

    auto futureHeader = unlocked.header();
    futureHeader.dbSchemaVersion = hepatizon::core::g_vaultDbSchemaVersionCurrent + 1U;

    const auto plain = hepatizon::core::encodeVaultHeaderV1(futureHeader);
    const auto aad = hepatizon::core::encodeVaultHeaderAadV1(unlocked.kdf());
    const auto encrypted =
        crypto.aeadEncrypt(unlocked.masterKey(), std::span<const std::byte>{ plain.data(), plain.size() },
                           std::span<const std::byte>{ aad.data(), aad.size() });
    try
    {
        storage->storeEncryptedHeader(dir, encrypted);
    }
    catch (...)
    {
        ADD_FAILURE() << "storeEncryptedHeader threw";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    const auto unlockAgain = service.unlockVault(dir, hepatizon::security::asBytes(password));
    if (!std::holds_alternative<hepatizon::core::VaultError>(unlockAgain) ||
        std::get<hepatizon::core::VaultError>(unlockAgain) != hepatizon::core::VaultError::MigrationRequired)
    {
        ADD_FAILURE() << "expected MigrationRequired for future schema";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    wipePassword.release();
    hepatizon::security::secureRelease(password);
    std::filesystem::remove_all(dir);
    return { ScenarioOutcome::Ok, {} };
}

[[nodiscard]] inline ScenarioResult runVaultServiceMigratesOldSchema(hepatizon::crypto::ICryptoProvider& crypto,
                                                                    std::string_view tempPrefix,
                                                                    bool allowSkipUnsupportedKdf) noexcept
{
    const auto dir = hepatizon::test_utils::makeSecureTempDir(tempPrefix);
    if (dir.empty())
    {
        ADD_FAILURE() << "failed to create temp dir";
        return { ScenarioOutcome::Failed, {} };
    }

    auto storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
    hepatizon::core::VaultService service{ crypto, *storage };

    auto password = hepatizon::security::secureStringFrom("correct horse battery staple");
    auto wipePassword = hepatizon::security::scopeWipe(password);

    const auto createRes = service.createVault(dir, hepatizon::security::asBytes(password), argon2idParamsForVaultTests());
    if (std::holds_alternative<hepatizon::core::VaultError>(createRes))
    {
        const auto err = std::get<hepatizon::core::VaultError>(createRes);
        if (allowSkipUnsupportedKdf && err == hepatizon::core::VaultError::UnsupportedKdfMetadata)
        {
            wipePassword.release();
            hepatizon::security::secureRelease(password);
            std::filesystem::remove_all(dir);
            return { ScenarioOutcome::Skip, "provider does not support Argon2id KDF at runtime" };
        }
        ADD_FAILURE() << "createVault failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    auto unlockRes = service.unlockVault(dir, hepatizon::security::asBytes(password));
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockRes))
    {
        ADD_FAILURE() << "unlockVault failed";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    const auto& unlocked = std::get<hepatizon::core::UnlockedVault>(unlockRes);

    auto oldHeader = unlocked.header();
    oldHeader.dbSchemaVersion = hepatizon::core::g_vaultDbSchemaVersionV0;

    const auto plain = hepatizon::core::encodeVaultHeaderV1(oldHeader);
    const auto aad = hepatizon::core::encodeVaultHeaderAadV1(unlocked.kdf());
    const auto encrypted =
        crypto.aeadEncrypt(unlocked.masterKey(), std::span<const std::byte>{ plain.data(), plain.size() },
                           std::span<const std::byte>{ aad.data(), aad.size() });
    try
    {
        storage->storeEncryptedHeader(dir, encrypted);
    }
    catch (...)
    {
        ADD_FAILURE() << "storeEncryptedHeader threw";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    auto unlockAfter = service.unlockVault(dir, hepatizon::security::asBytes(password));
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockAfter))
    {
        ADD_FAILURE() << "unlockVault failed after migration";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }
    const auto& unlockedAfter = std::get<hepatizon::core::UnlockedVault>(unlockAfter);
    if (unlockedAfter.header().dbSchemaVersion != hepatizon::core::g_vaultDbSchemaVersionCurrent)
    {
        ADD_FAILURE() << "migration did not update schema version";
        wipePassword.release();
        hepatizon::security::secureRelease(password);
        std::filesystem::remove_all(dir);
        return { ScenarioOutcome::Failed, {} };
    }

    wipePassword.release();
    hepatizon::security::secureRelease(password);
    std::filesystem::remove_all(dir);
    return { ScenarioOutcome::Ok, {} };
}

} // namespace hepatizon::test_utils

#endif // HEPATIZON_TESTS_TEST_UTILS_VAULTSERVICESCENARIOS_HPP
