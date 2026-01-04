#ifndef HEPATIZON_SRC_CORE_LITTLEENDIAN_HPP
#define HEPATIZON_SRC_CORE_LITTLEENDIAN_HPP

#include <cstddef>
#include <cstdint>
#include <span>

namespace hepatizon::core::detail
{

constexpr std::size_t kU32Bytes{ sizeof(std::uint32_t) };
constexpr std::size_t kU64Bytes{ sizeof(std::uint64_t) };

constexpr std::uint64_t kByteMaskU64{ 0xFFU };
constexpr std::uint64_t kBitsPerByte{ 8U };

inline void writeU32LE(std::span<std::byte, kU32Bytes> out, std::uint32_t v) noexcept
{
    for (std::size_t i{}; i < out.size(); ++i)
    {
        const std::uint32_t shiftBits = static_cast<std::uint32_t>(i) * static_cast<std::uint32_t>(kBitsPerByte);
        out[i] = static_cast<std::byte>((v >> shiftBits) & static_cast<std::uint32_t>(kByteMaskU64));
    }
}

inline void writeU64LE(std::span<std::byte, kU64Bytes> out, std::uint64_t v) noexcept
{
    for (std::size_t i{}; i < out.size(); ++i)
    {
        const std::uint64_t shiftBits = static_cast<std::uint64_t>(i) * kBitsPerByte;
        out[i] = static_cast<std::byte>((v >> shiftBits) & kByteMaskU64);
    }
}

[[nodiscard]] inline std::uint32_t readU32LE(std::span<const std::byte, kU32Bytes> in) noexcept
{
    std::uint32_t v{ 0U };
    for (std::size_t i{}; i < in.size(); ++i)
    {
        const std::uint32_t shiftBits = static_cast<std::uint32_t>(i) * static_cast<std::uint32_t>(kBitsPerByte);
        v |= (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[i])) << shiftBits);
    }
    return v;
}

[[nodiscard]] inline std::uint64_t readU64LE(std::span<const std::byte, kU64Bytes> in) noexcept
{
    std::uint64_t v{ 0U };
    for (std::size_t i{}; i < in.size(); ++i)
    {
        const std::uint64_t shiftBits = static_cast<std::uint64_t>(i) * kBitsPerByte;
        v |= (static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(in[i])) << shiftBits);
    }
    return v;
}

} // namespace hepatizon::core::detail

#endif // HEPATIZON_SRC_CORE_LITTLEENDIAN_HPP
