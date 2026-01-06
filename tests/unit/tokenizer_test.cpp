#include "Tokenizer.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

TEST(TokenizerTest, TokenizesSimpleWords)
{
    auto result = hepatizon::ui::cli::Tokenizer::tokenize("hello world test");
    EXPECT_THAT(result, ::testing::ElementsAre("hello", "world", "test"));
}

TEST(TokenizerTest, HandlesExcessiveWhitespace)
{
    auto result = hepatizon::ui::cli::Tokenizer::tokenize("   hello    world   ");
    EXPECT_THAT(result, ::testing::ElementsAre("hello", "world"));
}

TEST(TokenizerTest, HandlesEmptyInput)
{
    EXPECT_TRUE(hepatizon::ui::cli::Tokenizer::tokenize("").empty());
    EXPECT_TRUE(hepatizon::ui::cli::Tokenizer::tokenize("   ").empty());
}

TEST(TokenizerTest, TokenizesPipesAsSeparators)
{
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("ls | grep"), ::testing::ElementsAre("ls", "|", "grep"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("ls|grep"), ::testing::ElementsAre("ls", "|", "grep"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("a||b"), ::testing::ElementsAre("a", "|", "|", "b"));
}

TEST(TokenizerTest, HandlesSingleQuotes)
{
    auto result = hepatizon::ui::cli::Tokenizer::tokenize("'hello world' 'pipe|test'");
    EXPECT_THAT(result, ::testing::ElementsAre("hello world", "pipe|test"));
}

TEST(TokenizerTest, HandlesDoubleQuotes)
{
    auto result = hepatizon::ui::cli::Tokenizer::tokenize("\"hello world\" \"foo bar\"");
    EXPECT_THAT(result, ::testing::ElementsAre("hello world", "foo bar"));
}

TEST(TokenizerTest, MixedQuotesAndConcatenation)
{
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("abc\"def\""), ::testing::ElementsAre("abcdef"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("'abc'\"def\""), ::testing::ElementsAre("abcdef"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("user=\"admin\""), ::testing::ElementsAre("user=admin"));
}

TEST(TokenizerTest, HandlesEscapingInNoneMode)
{
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("a\\ b"), ::testing::ElementsAre("a b"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\\\\"), ::testing::ElementsAre("\\"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\\|"), ::testing::ElementsAre("|"));
}

TEST(TokenizerTest, HandlesEscapingInDoubleQuotes)
{
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\"quote\\\"here\""), ::testing::ElementsAre("quote\"here"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\"back\\\\slash\""), ::testing::ElementsAre("back\\slash"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\"cost\\$5\""), ::testing::ElementsAre("cost$5"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\"cmd\\`\""), ::testing::ElementsAre("cmd`"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\"path\\to\\file\""),
                ::testing::ElementsAre("path\\to\\file"));
}

TEST(TokenizerTest, HandlesUnclosedQuotes)
{
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("\"abc"), ::testing::ElementsAre("abc"));
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("'abc"), ::testing::ElementsAre("abc"));
}

TEST(TokenizerTest, EdgeCaseTrailingBackslash)
{
    EXPECT_THAT(hepatizon::ui::cli::Tokenizer::tokenize("abc\\"), ::testing::ElementsAre("abc\\"));
}