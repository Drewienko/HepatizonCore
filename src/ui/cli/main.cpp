#include "hepatizon/core/VaultService.hpp"

#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/security/ScopeWipe.hpp"
#include "hepatizon/security/SecureString.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <variant>

#if defined(HEPC_ENABLE_OPENSSL)
#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
#endif

namespace
{

void runScenario(std::string_view name, hepatizon::crypto::ICryptoProvider& crypto)
{
    std::cout << "== " << name << " ==\n";

    auto storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();
    hepatizon::core::VaultService service{ crypto, *storage };

    const std::filesystem::path vaultDir =
        std::filesystem::temp_directory_path() / ("hepatizoncore_dev_vault_" + std::string{name});

    auto password = hepatizon::security::secureStringFrom("correct horse battery staple");
    auto wipePassword = hepatizon::security::scopeWipe(password);

    auto createRes = service.createVault(vaultDir, hepatizon::security::asBytes(password));
    if (std::holds_alternative<hepatizon::core::VaultError>(createRes))
    {
        std::cout << "createVault failed\n";
        return;
    }
    std::cout << "vault created at: " << vaultDir.string() << "\n";

    auto unlockRes = service.unlockVault(vaultDir, hepatizon::security::asBytes(password));
    if (std::holds_alternative<hepatizon::core::VaultError>(unlockRes))
    {
        std::cout << "unlockVault failed\n";
        return;
    }

    const auto& unlocked = std::get<hepatizon::core::UnlockedVault>(unlockRes);
    std::cout << "unlocked: dbSchemaVersion=" << unlocked.header().dbSchemaVersion << "\n";

    constexpr std::string_view kKey{ "demo.secret" };
    auto value = hepatizon::security::secureStringFrom("demo value");
    auto wipeValue = hepatizon::security::scopeWipe(value);

    const auto putRes = service.putSecret(vaultDir, unlocked, kKey, value);
    if (!std::holds_alternative<std::monostate>(putRes))
    {
        std::cout << "putSecret failed\n";
        return;
    }

    const auto getRes = service.getSecret(vaultDir, unlocked, kKey);
    if (!std::holds_alternative<hepatizon::security::SecureString>(getRes))
    {
        std::cout << "getSecret failed\n";
        return;
    }

    auto loaded = std::get<hepatizon::security::SecureString>(getRes);
    auto wipeLoaded = hepatizon::security::scopeWipe(loaded);
    std::cout << "getSecret: " << hepatizon::security::asStringView(loaded) << "\n";
}

} // namespace

int main()
{
    try
    {
        auto native = hepatizon::crypto::providers::makeNativeCryptoProvider();
        runScenario("native", *native);

#if defined(HEPC_ENABLE_OPENSSL)
        auto openssl = hepatizon::crypto::providers::makeOpenSslCryptoProvider();
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
