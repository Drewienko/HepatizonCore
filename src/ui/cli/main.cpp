#include "ConsoleUtils.hpp"
#include "InteractiveShell.hpp"

#include "hepatizon/core/VaultService.hpp"
#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "hepatizon/storage/sqlite/SqliteStorageRepositoryFactory.hpp"

#if defined(HEPC_ENABLE_OPENSSL)
#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
#endif

#include <CLI/CLI.hpp>
#include <iostream>
#include <memory>

int main(int argc, char** argv)
{
    // Security: Lock RAM to prevent swapping secrets to disk.
    // This ensures keys derived later won't accidentally hit the swap partition.
    hepatizon::ui::cli::lockProcessMemory();

    CLI::App app{ "HepatizonCore CLI" };
    argv = app.ensure_utf8(argv);

#if defined(HEPC_ENABLE_OPENSSL)
    bool useOpenssl = false;
    app.add_flag("--openssl", useOpenssl, "Use OpenSSL crypto provider explicitly");
#endif

    app.allow_extras(true);

    CLI11_PARSE(app, argc, argv);

    try
    {
        std::unique_ptr<hepatizon::crypto::ICryptoProvider> crypto;

#if defined(HEPC_ENABLE_OPENSSL)
        if (useOpenssl)
        {
            crypto = hepatizon::crypto::providers::makeOpenSslCryptoProvider();
            std::cout << "[Info] Backend: OpenSSL\n";
        }
        else
        {
            crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
            std::cout << "[Info] Backend: Native (Monocypher)\n";
        }
#else
        crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
#endif

        auto storage = hepatizon::storage::sqlite::makeSqliteStorageRepository();

        hepatizon::core::VaultService service(*crypto, *storage);

        hepatizon::ui::cli::InteractiveShell shell(service, std::cin, std::cout, [](const std::string& prompt)
                                                   { return hepatizon::ui::cli::readPassword(prompt); });

        return shell.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Fatal Error: " << e.what() << "\n";
        return 1;
    }
}