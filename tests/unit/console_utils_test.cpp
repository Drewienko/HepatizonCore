#include "ConsoleUtils.hpp"
#include "hepatizon/security/SecureString.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>

#if defined(__linux__)
#include <sys/mman.h>
#endif

struct StreamRedirector
{
    std::streambuf* oldCin;
    std::streambuf* oldCout;
    std::stringstream input;
    std::stringstream output;

    explicit StreamRedirector(const std::string& inputData) : oldCin(std::cin.rdbuf()), oldCout(std::cout.rdbuf())
    {
        input << inputData;
        std::cin.rdbuf(input.rdbuf());
        std::cout.rdbuf(output.rdbuf());
    }

    ~StreamRedirector()
    {
        std::cin.rdbuf(oldCin);
        std::cout.rdbuf(oldCout);
    }
};

TEST(ConsoleUtilsTest, LockProcessMemoryIsSafeToCall)
{
    EXPECT_NO_THROW(hepatizon::ui::cli::lockProcessMemory());

#if defined(__linux__)
    munlockall();
#endif
}

TEST(ConsoleUtilsTest, ReadPasswordConsumesInputAndPrintsPrompt)
{
    StreamRedirector redirect("secret123\n");

    std::string prompt = "Enter Password: ";

    auto result = hepatizon::ui::cli::readPassword(prompt);

    EXPECT_EQ(hepatizon::security::asStringView(result), "secret123");

    std::string expectedOutput = prompt + "\n";
    EXPECT_EQ(redirect.output.str(), expectedOutput);
}

TEST(ConsoleUtilsTest, ReadPasswordHandlesEmptyInput)
{
    StreamRedirector redirect("\n");

    auto result = hepatizon::ui::cli::readPassword("Pass: ");

    EXPECT_TRUE(hepatizon::security::asStringView(result).empty());
}