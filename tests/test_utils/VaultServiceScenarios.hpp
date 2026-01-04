#ifndef HEPATIZON_TESTS_TEST_UTILS_VAULTSERVICESCENARIOS_HPP
#define HEPATIZON_TESTS_TEST_UTILS_VAULTSERVICESCENARIOS_HPP

#include "hepatizon/core/KdfPolicy.hpp"
#include "hepatizon/core/VaultHeaderAad.hpp"
#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include "test_utils/TestUtils.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string_view>
#include <system_error>
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
    std::string_view skipReason;
};

[[nodiscard]] inline hepatizon::crypto::Argon2idParams argon2idParamsForVaultTests() noexcept;

namespace detail
{

class ScenarioCleanup final
{
public:
    explicit ScenarioCleanup(std::filesystem::path d) : m_dir{ std::move(d) }
    {
    }

    ScenarioCleanup(const ScenarioCleanup&) = delete;
    ScenarioCleanup& operator=(const ScenarioCleanup&) = delete;

    ~ScenarioCleanup() noexcept
    {
        hepatizon::security::secureRelease(m_password);

        std::error_code ec{};
        if (!m_dir.empty())
        {
            std::filesystem::remove_all(m_dir, ec);
        }
    }

    [[nodiscard]] std::filesystem::path& dir() noexcept
    {
        return m_dir;
    }

    [[nodiscard]] const std::filesystem::path& dir() const noexcept
    {
        return m_dir;
    }

    [[nodiscard]] hepatizon::security::SecureString& password() noexcept
    {
        return m_password;
    }

    [[nodiscard]] const hepatizon::security::SecureString& password() const noexcept
    {
        return m_password;
    }

private:
    std::filesystem::path m_dir;
    hepatizon::security::SecureString m_password;
};

[[nodiscard]] inline bool initScenarioPassword(ScenarioCleanup& cleanup) noexcept
{
    // Avoid hard-coded passwords in tests: generate a per-run random passphrase.
    constexpr std::size_t kTokenBytes{ 16U };
    constexpr char kHex[] = "0123456789abcdef";
    constexpr std::uint8_t kNibbleShift{ 4U };
    constexpr std::uint8_t kNibbleMask{ 0x0FU };

    std::array<std::uint8_t, kTokenBytes> rnd{};
    if (!hepatizon::security::secureRandomFill(std::span<std::uint8_t>{ rnd }))
    {
        return false;
    }

    cleanup.password().resize(kTokenBytes * 2U);
    for (std::size_t i{}; i < rnd.size(); ++i)
    {
        const std::uint8_t b{ rnd[i] };
        cleanup.password()[(i * 2U) + 0U] = kHex[(b >> kNibbleShift) & kNibbleMask];
        cleanup.password()[(i * 2U) + 1U] = kHex[b & kNibbleMask];
    }
    return true;
}

[[nodiscard]] inline std::variant<std::filesystem::path, ScenarioResult>
makeTempDirOrFail(std::string_view prefix) noexcept
{
    auto dir{ hepatizon::test_utils::makeSecureTempDir(prefix) };
    if (dir.empty())
    {
        ADD_FAILURE() << "failed to create temp dir";
        return ScenarioResult{ ScenarioOutcome::Failed, {} };
    }
    return dir;
}

[[nodiscard]] inline std::variant<hepatizon::core::CreatedVault, ScenarioResult>
createVaultOrResult(hepatizon::core::VaultService& service, const std::filesystem::path& dir,
                    hepatizon::security::SecureString& password, bool allowSkipUnsupportedKdf) noexcept
{
    const auto createRes{ service.createVault(dir, hepatizon::security::asBytes(password),
                                              hepatizon::test_utils::argon2idParamsForVaultTests()) };
    if (std::holds_alternative<hepatizon::core::VaultError>(createRes))
    {
        const auto err{ std::get<hepatizon::core::VaultError>(createRes) };
        if (allowSkipUnsupportedKdf && err == hepatizon::core::VaultError::UnsupportedKdfMetadata)
        {
            return ScenarioResult{ ScenarioOutcome::Skip, "provider does not support Argon2id KDF at runtime" };
        }
        ADD_FAILURE() << "createVault failed: " << static_cast<int>(err);
        return ScenarioResult{ ScenarioOutcome::Failed, {} };
    }
    return std::get<hepatizon::core::CreatedVault>(createRes);
}

[[nodiscard]] inline std::variant<hepatizon::core::UnlockedVault, ScenarioResult>
unlockVaultOrResult(hepatizon::core::VaultService& service, const std::filesystem::path& dir,
                    const hepatizon::security::SecureString& password) noexcept
{
    auto unlockRes{ service.unlockVault(dir, hepatizon::security::asBytes(password)) };
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockRes))
    {
        ADD_FAILURE() << "unlockVault failed";
        return ScenarioResult{ ScenarioOutcome::Failed, {} };
    }
    return std::move(std::get<hepatizon::core::UnlockedVault>(unlockRes));
}

} // namespace detail

[[nodiscard]] inline hepatizon::crypto::Argon2idParams argon2idParamsForVaultTests() noexcept
{
    if (hepatizon::test_utils::envFlagSet("HEPC_RUN_SLOW_TESTS"))
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
    auto dirOrErr{ detail::makeTempDirOrFail(tempPrefix) };
    if (std::holds_alternative<ScenarioResult>(dirOrErr))
    {
        return std::get<ScenarioResult>(dirOrErr);
    }
    detail::ScenarioCleanup cleanup{ std::move(std::get<std::filesystem::path>(dirOrErr)) };
    if (!detail::initScenarioPassword(cleanup))
    {
        ADD_FAILURE() << "CSPRNG failure";
        return { ScenarioOutcome::Failed, {} };
    }

    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ crypto, *storage };

    const auto createdOrErr{ detail::createVaultOrResult(service, cleanup.dir(), cleanup.password(),
                                                         allowSkipUnsupportedKdf) };
    if (std::holds_alternative<ScenarioResult>(createdOrErr))
    {
        return std::get<ScenarioResult>(createdOrErr);
    }
    const auto created{ std::get<hepatizon::core::CreatedVault>(createdOrErr) };

    auto unlockedOrErr{ detail::unlockVaultOrResult(service, cleanup.dir(), cleanup.password()) };
    if (std::holds_alternative<ScenarioResult>(unlockedOrErr))
    {
        return std::get<ScenarioResult>(unlockedOrErr);
    }
    auto unlocked{ std::get<hepatizon::core::UnlockedVault>(std::move(unlockedOrErr)) };

    // AEAD authentication should fail if AAD does not match (empty AAD here).
    try
    {
        const auto storedInfo{ storage->loadVaultInfo(cleanup.dir()) };
        const auto wrongAad{ crypto.aeadDecrypt(unlocked.masterKey(), storedInfo.encryptedHeader, {}) };
        if (wrongAad.has_value())
        {
            ADD_FAILURE() << "decrypting with wrong AAD unexpectedly succeeded";
            return { ScenarioOutcome::Failed, {} };
        }
    }
    catch (...)
    {
        ADD_FAILURE() << "storage read/decrypt threw during wrong-AAD check";
        return { ScenarioOutcome::Failed, {} };
    }

    if (unlocked.kdf().policyVersion != created.kdf().policyVersion ||
        static_cast<std::uint32_t>(unlocked.kdf().algorithm) != static_cast<std::uint32_t>(created.kdf().algorithm) ||
        unlocked.kdf().argon2Version != created.kdf().argon2Version ||
        unlocked.kdf().derivedKeyBytes != created.kdf().derivedKeyBytes ||
        unlocked.kdf().argon2id.iterations != created.kdf().argon2id.iterations ||
        unlocked.kdf().argon2id.memoryKiB != created.kdf().argon2id.memoryKiB ||
        unlocked.kdf().argon2id.parallelism != created.kdf().argon2id.parallelism ||
        unlocked.kdf().salt != created.kdf().salt)
    {
        ADD_FAILURE() << "KdfMetadata mismatch after unlock";
        return { ScenarioOutcome::Failed, {} };
    }

    if (unlocked.header().headerVersion != hepatizon::core::g_vaultHeaderVersionV1 ||
        unlocked.header().vaultId != created.header().vaultId ||
        unlocked.header().createdAtUnixSeconds != created.header().createdAtUnixSeconds ||
        unlocked.header().dbSchemaVersion != hepatizon::core::g_vaultDbSchemaVersionCurrent ||
        unlocked.header().flags != 0U)
    {
        ADD_FAILURE() << "VaultHeader mismatch after unlock";
        return { ScenarioOutcome::Failed, {} };
    }

    if (unlocked.masterKey().empty())
    {
        ADD_FAILURE() << "master key is empty";
        return { ScenarioOutcome::Failed, {} };
    }

    constexpr std::string_view kKey{ "demo.secret" };
    constexpr std::string_view kValue{ "demo value" };

    auto value{ hepatizon::security::secureStringFrom(kValue) };
    auto wipeValue{ hepatizon::security::scopeWipe(value) };
    const auto putRes{ service.putSecret(cleanup.dir(), unlocked, kKey, value) };
    wipeValue.release();
    hepatizon::security::secureRelease(value);
    if (!std::holds_alternative<std::monostate>(putRes))
    {
        ADD_FAILURE() << "putSecret failed";
        return { ScenarioOutcome::Failed, {} };
    }

    auto getRes{ service.getSecret(cleanup.dir(), unlocked, kKey) };
    if (!std::holds_alternative<hepatizon::security::SecureString>(getRes))
    {
        ADD_FAILURE() << "getSecret failed";
        return { ScenarioOutcome::Failed, {} };
    }
    auto loaded{ std::get<hepatizon::security::SecureString>(getRes) };
    auto wipeLoaded{ hepatizon::security::scopeWipe(loaded) };
    if (hepatizon::security::asStringView(loaded) != kValue)
    {
        ADD_FAILURE() << "secret value mismatch";
        wipeLoaded.release();
        hepatizon::security::secureRelease(loaded);
        return { ScenarioOutcome::Failed, {} };
    }
    wipeLoaded.release();
    hepatizon::security::secureRelease(loaded);

    const auto missingRes{ service.getSecret(cleanup.dir(), unlocked, "missing.key") };
    if (!std::holds_alternative<hepatizon::core::VaultError>(missingRes) ||
        std::get<hepatizon::core::VaultError>(missingRes) != hepatizon::core::VaultError::NotFound)
    {
        ADD_FAILURE() << "missing key did not return NotFound";
        return { ScenarioOutcome::Failed, {} };
    }

    // Wrong password should fail authentication (but not crash).
    auto wrongPassword{ cleanup.password() };
    if (wrongPassword.empty())
    {
        ADD_FAILURE() << "test invariant violated: password is empty";
        return { ScenarioOutcome::Failed, {} };
    }
    wrongPassword[0] = (wrongPassword[0] == '0') ? '1' : '0';
    auto wipeWrongPassword{ hepatizon::security::scopeWipe(wrongPassword) };
    const auto wrongUnlock{ service.unlockVault(cleanup.dir(), hepatizon::security::asBytes(wrongPassword)) };
    wipeWrongPassword.release();
    hepatizon::security::secureRelease(wrongPassword);
    if (!std::holds_alternative<hepatizon::core::VaultError>(wrongUnlock) ||
        std::get<hepatizon::core::VaultError>(wrongUnlock) != hepatizon::core::VaultError::AuthFailed)
    {
        ADD_FAILURE() << "wrong password did not return AuthFailed";
        return { ScenarioOutcome::Failed, {} };
    }

    return { ScenarioOutcome::Ok, {} };
}

[[nodiscard]] inline ScenarioResult runVaultServiceRejectsFutureSchema(hepatizon::crypto::ICryptoProvider& crypto,
                                                                       std::string_view tempPrefix,
                                                                       bool allowSkipUnsupportedKdf) noexcept
{
    auto dirOrErr{ detail::makeTempDirOrFail(tempPrefix) };
    if (std::holds_alternative<ScenarioResult>(dirOrErr))
    {
        return std::get<ScenarioResult>(dirOrErr);
    }
    detail::ScenarioCleanup cleanup{ std::move(std::get<std::filesystem::path>(dirOrErr)) };
    if (!detail::initScenarioPassword(cleanup))
    {
        ADD_FAILURE() << "CSPRNG failure";
        return { ScenarioOutcome::Failed, {} };
    }

    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ crypto, *storage };

    const auto createdOrErr{ detail::createVaultOrResult(service, cleanup.dir(), cleanup.password(),
                                                         allowSkipUnsupportedKdf) };
    if (std::holds_alternative<ScenarioResult>(createdOrErr))
    {
        return std::get<ScenarioResult>(createdOrErr);
    }
    (void)std::get<hepatizon::core::CreatedVault>(createdOrErr);

    auto unlockedOrErr{ detail::unlockVaultOrResult(service, cleanup.dir(), cleanup.password()) };
    if (std::holds_alternative<ScenarioResult>(unlockedOrErr))
    {
        return std::get<ScenarioResult>(unlockedOrErr);
    }
    const auto unlocked{ std::get<hepatizon::core::UnlockedVault>(std::move(unlockedOrErr)) };

    auto futureHeader{ unlocked.header() };
    futureHeader.dbSchemaVersion = hepatizon::core::g_vaultDbSchemaVersionCurrent + 1U;

    const auto plain{ hepatizon::core::encodeVaultHeaderV1(futureHeader) };
    const auto aad{ hepatizon::core::encodeVaultHeaderAadV1(unlocked.kdf()) };
    const auto encrypted{ crypto.aeadEncrypt(unlocked.masterKey(),
                                             std::span<const std::byte>{ plain.data(), plain.size() },
                                             std::span<const std::byte>{ aad.data(), aad.size() }) };
    try
    {
        storage->storeEncryptedHeader(cleanup.dir(), encrypted);
    }
    catch (...)
    {
        ADD_FAILURE() << "storeEncryptedHeader threw";
        return { ScenarioOutcome::Failed, {} };
    }

    const auto unlockAgain{ service.unlockVault(cleanup.dir(), hepatizon::security::asBytes(cleanup.password())) };
    if (!std::holds_alternative<hepatizon::core::VaultError>(unlockAgain) ||
        std::get<hepatizon::core::VaultError>(unlockAgain) != hepatizon::core::VaultError::MigrationRequired)
    {
        ADD_FAILURE() << "expected MigrationRequired for future schema";
        return { ScenarioOutcome::Failed, {} };
    }

    return { ScenarioOutcome::Ok, {} };
}

[[nodiscard]] inline ScenarioResult runVaultServiceMigratesOldSchema(hepatizon::crypto::ICryptoProvider& crypto,
                                                                     std::string_view tempPrefix,
                                                                     bool allowSkipUnsupportedKdf) noexcept
{
    auto dirOrErr{ detail::makeTempDirOrFail(tempPrefix) };
    if (std::holds_alternative<ScenarioResult>(dirOrErr))
    {
        return std::get<ScenarioResult>(dirOrErr);
    }
    detail::ScenarioCleanup cleanup{ std::move(std::get<std::filesystem::path>(dirOrErr)) };
    if (!detail::initScenarioPassword(cleanup))
    {
        ADD_FAILURE() << "CSPRNG failure";
        return { ScenarioOutcome::Failed, {} };
    }

    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ crypto, *storage };

    const auto createdOrErr{ detail::createVaultOrResult(service, cleanup.dir(), cleanup.password(),
                                                         allowSkipUnsupportedKdf) };
    if (std::holds_alternative<ScenarioResult>(createdOrErr))
    {
        return std::get<ScenarioResult>(createdOrErr);
    }
    (void)std::get<hepatizon::core::CreatedVault>(createdOrErr);

    auto unlockedOrErr{ detail::unlockVaultOrResult(service, cleanup.dir(), cleanup.password()) };
    if (std::holds_alternative<ScenarioResult>(unlockedOrErr))
    {
        return std::get<ScenarioResult>(unlockedOrErr);
    }
    const auto unlocked{ std::get<hepatizon::core::UnlockedVault>(std::move(unlockedOrErr)) };

    auto oldHeader{ unlocked.header() };
    oldHeader.dbSchemaVersion = hepatizon::core::g_vaultDbSchemaVersionV0;

    const auto plain{ hepatizon::core::encodeVaultHeaderV1(oldHeader) };
    const auto aad{ hepatizon::core::encodeVaultHeaderAadV1(unlocked.kdf()) };
    const auto encrypted{ crypto.aeadEncrypt(unlocked.masterKey(),
                                             std::span<const std::byte>{ plain.data(), plain.size() },
                                             std::span<const std::byte>{ aad.data(), aad.size() }) };
    try
    {
        storage->storeEncryptedHeader(cleanup.dir(), encrypted);
    }
    catch (...)
    {
        ADD_FAILURE() << "storeEncryptedHeader threw";
        return { ScenarioOutcome::Failed, {} };
    }

    auto unlockAfter{ service.unlockVault(cleanup.dir(), hepatizon::security::asBytes(cleanup.password())) };
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockAfter))
    {
        ADD_FAILURE() << "unlockVault failed after migration";
        return { ScenarioOutcome::Failed, {} };
    }
    const auto& unlockedAfter = std::get<hepatizon::core::UnlockedVault>(unlockAfter);
    if (unlockedAfter.header().dbSchemaVersion != hepatizon::core::g_vaultDbSchemaVersionCurrent)
    {
        ADD_FAILURE() << "migration did not update schema version";
        return { ScenarioOutcome::Failed, {} };
    }

    return { ScenarioOutcome::Ok, {} };
}

} // namespace hepatizon::test_utils

#endif // HEPATIZON_TESTS_TEST_UTILS_VAULTSERVICESCENARIOS_HPP
