#include "hepatizon/core/VaultService.hpp"

#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include "hepatizon/security/SecureRandom.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>

#if defined(HEPC_ENABLE_OPENSSL)
#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
#endif

namespace
{

std::string toHex(std::span<const std::uint8_t> bytes)
{
    constexpr char kHex[] = "0123456789abcdef";
    constexpr std::uint8_t kNibbleShift{ 4U };
    constexpr std::uint8_t kNibbleMask{ 0x0FU };

    std::string out{};
    out.reserve(bytes.size() * 2U);
    for (const std::uint8_t b : bytes)
    {
        out.push_back(kHex[(b >> kNibbleShift) & kNibbleMask]);
        out.push_back(kHex[b & kNibbleMask]);
    }
    return out;
}

[[nodiscard]] std::filesystem::path makeSecureTempDir(std::string_view prefix)
{
    constexpr std::size_t kTokenBytes{ 16U };
    constexpr std::size_t kMaxAttempts{ 16U };

    std::error_code ec{};
    const std::filesystem::path base{ std::filesystem::temp_directory_path() /
                                      std::filesystem::path{ "hepatizoncore_cli" } };

    ec.clear();
    if (!std::filesystem::create_directories(base, ec) && ec)
    {
        return {};
    }
    ec.clear();
    if (!std::filesystem::is_directory(base, ec) || ec)
    {
        return {};
    }

#if !defined(_WIN32)
    ec.clear();
    std::filesystem::permissions(base, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
    if (ec)
    {
        return {};
    }
    ec.clear();
    const auto perms{ std::filesystem::status(base, ec).permissions() };
    if (ec)
    {
        return {};
    }
    const auto publicBits{ std::filesystem::perms::group_all | std::filesystem::perms::others_all };
    if ((perms & publicBits) != std::filesystem::perms::none)
    {
        return {};
    }
#endif

    for (std::size_t attempt{}; attempt < kMaxAttempts; ++attempt)
    {
        std::array<std::uint8_t, kTokenBytes> rnd{};
        if (!hepatizon::security::secureRandomFill(std::span<std::uint8_t>{ rnd }))
        {
            break;
        }

        std::string name{ prefix };
        name += "_";
        name += toHex(std::span<const std::uint8_t>{ rnd });
        const std::filesystem::path dir{ base / std::filesystem::path{ name } };
        if (std::filesystem::create_directory(dir, ec) && !ec)
        {
#if !defined(_WIN32)
            ec.clear();
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace,
                                         ec);
            if (ec)
            {
                ec.clear();
                std::filesystem::remove_all(dir, ec);
                continue;
            }
#endif
            return dir;
        }
        ec.clear();
    }

    return {};
}

[[nodiscard]] hepatizon::security::SecureString randomHexPassword()
{
    constexpr std::size_t kTokenBytes{ 16U };
    std::array<std::uint8_t, kTokenBytes> rnd{};
    if (!hepatizon::security::secureRandomFill(std::span<std::uint8_t>{ rnd }))
    {
        throw std::runtime_error("CSPRNG failure");
    }

    const std::string hex{ toHex(std::span<const std::uint8_t>{ rnd }) };
    return hepatizon::security::secureStringFrom(hex);
}

void runScenario(std::string_view name, hepatizon::crypto::ICryptoProvider& crypto)
{
    std::cout << "== " << name << " ==\n";

    auto storage{ hepatizon::storage::sqlite::makeSqliteStorageRepository() };
    hepatizon::core::VaultService service{ crypto, *storage };

    const std::filesystem::path vaultDir{ makeSecureTempDir(std::string{ "hepatizoncore_vault_" } +
                                                            std::string{ name }) };
    if (vaultDir.empty())
    {
        std::cout << "failed to create temp dir\n";
        return;
    }
    class VaultDirCleanup final
    {
    public:
        explicit VaultDirCleanup(std::filesystem::path p) : m_path{ std::move(p) }
        {
        }
        VaultDirCleanup(const VaultDirCleanup&) = delete;
        VaultDirCleanup& operator=(const VaultDirCleanup&) = delete;
        ~VaultDirCleanup() noexcept
        {
            std::error_code ec{};
            if (!m_path.empty())
            {
                std::filesystem::remove_all(m_path, ec);
            }
        }

    private:
        std::filesystem::path m_path;
    } cleanup{ vaultDir };

    auto password{ randomHexPassword() };
    auto wipePassword{ hepatizon::security::scopeWipe(password) };

    auto createRes{ service.createVault(vaultDir, password) };
    if (std::holds_alternative<hepatizon::core::VaultError>(createRes))
    {
        std::cout << "createVault failed\n";
        return;
    }
    std::cout << "vault created at: " << vaultDir.string() << "\n";

    auto unlockRes{ service.openVault(vaultDir, password) };
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockRes))
    {
        std::cout << "unlockVault failed\n";
        return;
    }

    const auto& unlocked{ std::get<hepatizon::core::UnlockedVault>(unlockRes) };
    std::cout << "unlocked: dbSchemaVersion=" << unlocked.header().dbSchemaVersion << "\n";

    constexpr std::string_view kKey{ "demo.secret" };
    auto value{ randomHexPassword() };
    auto wipeValue{ hepatizon::security::scopeWipe(value) };

    const auto putRes{ service.putSecret(vaultDir, unlocked, kKey, value) };
    if (!std::holds_alternative<std::monostate>(putRes))
    {
        std::cout << "putSecret failed\n";
        return;
    }

    const auto getRes{ service.getSecret(vaultDir, unlocked, kKey) };
    if (!std::holds_alternative<hepatizon::security::SecureString>(getRes))
    {
        std::cout << "getSecret failed\n";
        return;
    }

    auto loaded{ std::get<hepatizon::security::SecureString>(getRes) };
    auto wipeLoaded{ hepatizon::security::scopeWipe(loaded) };
    std::cout << "getSecret ok (bytes=" << loaded.size() << ")\n";
}

} // namespace

int main()
{
    try
    {
        auto native{ hepatizon::crypto::providers::makeNativeCryptoProvider() };
        runScenario("native", *native);

#if defined(HEPC_ENABLE_OPENSSL)
        auto openssl{ hepatizon::crypto::providers::makeOpenSslCryptoProvider() };
        runScenario("openssl", *openssl);
#endif

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }
}
