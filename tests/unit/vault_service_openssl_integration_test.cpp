#include "hepatizon/crypto/providers/OpenSslProviderFactory.hpp"
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
    auto crypto = hepatizon::crypto::providers::makeOpenSslCryptoProvider();
    const auto res =
        hepatizon::test_utils::runVaultServiceCreateUnlockAndSecrets(*crypto, "vault_service_openssl_", true);
    maybeSkip(res);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, RejectsFutureSchemaWithOpenSslProvider)
{
    auto crypto = hepatizon::crypto::providers::makeOpenSslCryptoProvider();
    const auto res = hepatizon::test_utils::runVaultServiceRejectsFutureSchema(*crypto, "vault_service_openssl_", true);
    maybeSkip(res);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, MigratesOldSchemaWithOpenSslProvider)
{
    auto crypto = hepatizon::crypto::providers::makeOpenSslCryptoProvider();
    const auto res = hepatizon::test_utils::runVaultServiceMigratesOldSchema(*crypto, "vault_service_openssl_", true);
    maybeSkip(res);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}
