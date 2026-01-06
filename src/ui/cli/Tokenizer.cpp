#include "Tokenizer.hpp"

#include <cctype>

namespace hepatizon::ui::cli
{

std::vector<std::string> Tokenizer::tokenize(const std::string& line)
{
    TokenState state{};
    Cursor cursor{ line };

    while (!cursor.atEnd())
    {
        switch (state.mode)
        {
        case Mode::Single:
            handleSingle(state, cursor);
            break;
        case Mode::Double:
            handleDouble(state, cursor);
            break;
        case Mode::None:
            handleNone(state, cursor);
            break;
        }
    }

    pushToken(state);
    return state.parts;
}

void Tokenizer::pushToken(TokenState& state)
{
    if (state.tokenStarted)
    {
        state.parts.push_back(state.currentToken);
    }
    state.currentToken.clear();
    state.tokenStarted = false;
}

void Tokenizer::handleSingle(TokenState& state, Cursor& cursor)
{
    char c{ cursor.current() };
    if (c == '\'')
    {
        state.mode = Mode::None;
        state.tokenStarted = true;
        cursor.advance();
        return;
    }

    state.currentToken.push_back(c);
    state.tokenStarted = true;
    cursor.advance();
}

void Tokenizer::handleDouble(TokenState& state, Cursor& cursor)
{
    char c{ cursor.current() };
    if (c == '"')
    {
        state.mode = Mode::None;
        state.tokenStarted = true;
        cursor.advance();
        return;
    }

    if (c == '\\' && cursor.hasNext())
    {
        char next{ cursor.next() };
        if (next == '"' || next == '\\' || next == '$' || next == '`')
        {
            state.currentToken.push_back(next);
            cursor.advance();
            cursor.advance();
        }
        else
        {
            state.currentToken.push_back(c);
            cursor.advance();
        }
        state.tokenStarted = true;
        return;
    }

    state.currentToken.push_back(c);
    state.tokenStarted = true;
    cursor.advance();
}

void Tokenizer::handleNone(TokenState& state, Cursor& cursor)
{
    char c{ cursor.current() };
    if (c == '|')
    {
        pushToken(state);
        state.parts.emplace_back("|");
        cursor.advance();
        return;
    }

    if (std::isspace(static_cast<unsigned char>(c)) != 0)
    {
        pushToken(state);
        cursor.advance();
        return;
    }

    if (c == '\'')
    {
        state.mode = Mode::Single;
        state.tokenStarted = true;
        cursor.advance();
        return;
    }
    if (c == '"')
    {
        state.mode = Mode::Double;
        state.tokenStarted = true;
        cursor.advance();
        return;
    }
    if (c == '\\' && cursor.hasNext())
    {
        state.currentToken.push_back(cursor.next());
        state.tokenStarted = true;
        cursor.advance();
        cursor.advance();
        return;
    }

    state.currentToken.push_back(c);
    state.tokenStarted = true;
    cursor.advance();
}

} // namespace hepatizon::ui::cli