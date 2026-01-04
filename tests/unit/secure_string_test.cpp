#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "hepatizon/security/SecureString.hpp"

TEST(SecureString, AsStringViewEmptyIsSafe)
{
    hepatizon::security::SecureString s{};
    const std::string_view v{ hepatizon::security::asStringView(s) };
    EXPECT_TRUE(v.empty());
}

TEST(SecureString, SecureStringFromCopiesBytes)
{
    constexpr std::string_view input{ "password" };
    hepatizon::security::SecureString s{ hepatizon::security::secureStringFrom(input) };

    const std::string_view v{ hepatizon::security::asStringView(s) };
    EXPECT_EQ(v, input);
}

TEST(SecureString, ToSecureBufferPreservesBytePatterns)
{
    constexpr char bytes[]{ '\x00', '\x7F', static_cast<char>(0x80), static_cast<char>(0xFF) };
    const std::string_view input{ bytes, sizeof(bytes) };

    const hepatizon::security::SecureString s{ hepatizon::security::secureStringFrom(input) };
    const hepatizon::security::SecureBuffer b{ hepatizon::security::toSecureBuffer(s) };

    ASSERT_EQ(b.size(), input.size());
    for (std::size_t i{ 0U }; i < b.size(); ++i)
    {
        EXPECT_EQ(b[i], static_cast<std::uint8_t>(static_cast<unsigned char>(bytes[i])));
    }
}

TEST(SecureString, SecureResizeShrinksAndPreservesPrefix)
{
    constexpr std::string_view input{ "secret-data" };
    constexpr std::size_t newSize{ 6U };

    hepatizon::security::SecureString s{ hepatizon::security::secureStringFrom(input) };
    hepatizon::security::secureResize(s, newSize);

    const std::string_view v{ hepatizon::security::asStringView(s) };
    ASSERT_EQ(v.size(), newSize);
    EXPECT_EQ(v, input.substr(0U, newSize));
}
