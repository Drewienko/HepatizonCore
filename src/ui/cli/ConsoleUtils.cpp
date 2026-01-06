#include "ConsoleUtils.hpp"

#include <iostream>
#include <string>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>
#else
#error "Unsupported platform"
#endif

namespace hepatizon::ui::cli
{

namespace
{
void setConsoleEcho(bool enable)
{
#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(hStdin, mode);
#elif defined(__linux__)
    struct termios tty
    {
    };
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable)
    {
        tty.c_lflag &= ~ECHO;
    }
    else
    {
        tty.c_lflag |= ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}
} // namespace

void lockProcessMemory() noexcept
{
#if defined(_WIN32)
    // TODO: VirtualLock implementation if needed later
#elif defined(__linux__)
    mlockall(MCL_CURRENT | MCL_FUTURE);
    struct rlimit lim
    {
        0, 0
    };
    setrlimit(RLIMIT_CORE, &lim);
#endif
}

hepatizon::security::SecureString readPassword(const std::string& prompt)
{
    std::cout << prompt << std::flush;

    setConsoleEcho(false);

    std::string line;
    std::getline(std::cin, line);

    setConsoleEcho(true);
    std::cout << "\n";

    auto sec = hepatizon::security::secureStringFrom(line);

    if (!line.empty())
    {
        volatile char* p = line.data();
        const std::size_t n = line.size();
        for (std::size_t i = 0; i < n; ++i)
        {
            p[i] = '\0';
        }
    }

    return sec;
}

} // namespace hepatizon::ui::cli