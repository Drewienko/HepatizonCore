#include "hepatizon/crypto/providers/NativeProviderFactory.hpp"
#include "test_utils/VaultServiceScenarios.hpp"
#include <gtest/gtest.h>

TEST(VaultService, CreateUnlockAndSecretsWithNativeProvider)
{
    auto crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
    const auto res =
        hepatizon::test_utils::runVaultServiceCreateUnlockAndSecrets(*crypto, "vault_service_native_", false);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, RejectsFutureSchemaWithNativeProvider)
{
    auto crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
    const auto res = hepatizon::test_utils::runVaultServiceRejectsFutureSchema(*crypto, "vault_service_native_", false);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}

TEST(VaultService, MigratesOldSchemaWithNativeProvider)
{
    auto crypto = hepatizon::crypto::providers::makeNativeCryptoProvider();
    const auto res = hepatizon::test_utils::runVaultServiceMigratesOldSchema(*crypto, "vault_service_native_", false);
    ASSERT_EQ(res.outcome, hepatizon::test_utils::ScenarioOutcome::Ok);
}
