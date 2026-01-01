#ifndef INCLUDE_HEPATIZON_SECURITY_ZEROALLOCATOR_HPP
#define INCLUDE_HEPATIZON_SECURITY_ZEROALLOCATOR_HPP

#include "hepatizon/security/MemoryWiper.hpp"
#include <cstddef>
#include <limits>
#include <new>
#include <span>
#include <type_traits>

namespace hepatizon::security
{
template <class T> struct ZeroAllocator
{
    ZeroAllocator() noexcept = default;

    template <class U> constexpr explicit ZeroAllocator([[maybe_unused]] const ZeroAllocator<U>& u) noexcept {};

    using value_type = T;
    using is_always_equal = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    T* allocate(std::size_t n)
    {
        if (n == 0U)
        {
            return nullptr;
        }
        if (n > (std::numeric_limits<std::size_t>::max() / sizeof(T)))
        {
            throw std::bad_array_new_length{};
        }
        return static_cast<T*>(::operator new(n * sizeof(T), std::align_val_t{ alignof(T) }));
    }
    void deallocate(T* p, std::size_t n) noexcept
    {
        if (p == nullptr)
        {
            return;
        }

        if (n != 0U)
        {
            secureWipe(std::span<std::byte>{ reinterpret_cast<std::byte*>(p), n * sizeof(T) });
        }
        ::operator delete(p, std::align_val_t{ alignof(T) });
    }
};

template <class T, class U>
constexpr bool operator==([[maybe_unused]] const ZeroAllocator<T>& t,
                          [[maybe_unused]] const ZeroAllocator<U>& u) noexcept
{
    return true;
}

} // namespace hepatizon::security

#endif // INCLUDE_HEPATIZON_SECURITY_ZEROALLOCATOR_HPP