#ifndef HEPATIZON_UI_CLI_TOKENIZER_HPP
#define HEPATIZON_UI_CLI_TOKENIZER_HPP

#include <string>
#include <vector>

namespace hepatizon::ui::cli
{

class Tokenizer
{
public:
    [[nodiscard]] static std::vector<std::string> tokenize(const std::string& line);

private:
    enum class Mode
    {
        None,
        Single,
        Double
    };

    struct TokenState
    {
        std::vector<std::string> parts;
        std::string currentToken;
        bool tokenStarted{ false };
        Mode mode{ Mode::None };
    };

    class Cursor
    {
    public:
        explicit Cursor(const std::string& l) : m_line(l)
        {
        }

        [[nodiscard]] bool atEnd() const
        {
            return m_index >= m_line.size();
        }

        [[nodiscard]] char current() const
        {
            return m_line[m_index];
        }

        [[nodiscard]] bool hasNext() const
        {
            return m_index + 1 < m_line.size();
        }

        [[nodiscard]] char next() const
        {
            return m_line[m_index + 1];
        }

        void advance()
        {
            ++m_index;
        }

    private:
        const std::string& m_line;
        std::size_t m_index{ 0 };
    };

    static void pushToken(TokenState& state);
    static void handleSingle(TokenState& state, Cursor& cursor);
    static void handleDouble(TokenState& state, Cursor& cursor);
    static void handleNone(TokenState& state, Cursor& cursor);
};

} // namespace hepatizon::ui::cli

#endif // HEPATIZON_UI_CLI_TOKENIZER_HPP