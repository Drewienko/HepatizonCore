#include <gtest/gtest.h>
#include <hepatizon/security/ZeroAllocator.hpp>
#include <limits>
#include <string>
#include <vector>

// Test normal container usage (Happy Path)
TEST(ZeroAllocatorTests, VectorAllocationAndResizing)
{
    constexpr int kTestVal1 = 42;
    constexpr int kTestVal2 = 100;
    constexpr size_t kInitialSize = 2;
    constexpr size_t kLargeSize = 1000;

    std::vector<int, hepatizon::security::ZeroAllocator<int>> secureVec;

    secureVec.push_back(kTestVal1);
    secureVec.push_back(kTestVal2);

    EXPECT_EQ(secureVec.size(), kInitialSize);
    EXPECT_EQ(secureVec[0], kTestVal1);

    // Forces re-allocation and wiping of old memory
    secureVec.resize(kLargeSize, 0);

    EXPECT_EQ(secureVec.size(), kLargeSize);
}

// Test Copy/Rebind Logic
TEST(ZeroAllocatorTests, ExplicitCopyConsistency)
{
    hepatizon::security::ZeroAllocator<int> alloc1;
    // Rebind constructor coverage
    hepatizon::security::ZeroAllocator<double> alloc2(alloc1);

    EXPECT_TRUE(alloc1 == alloc1);
    EXPECT_FALSE(alloc1 != alloc1);
    EXPECT_TRUE(alloc1 == alloc2);
}

TEST(ZeroAllocatorTests, EqualityAndInequality)
{
    hepatizon::security::ZeroAllocator<int> a1;
    hepatizon::security::ZeroAllocator<int> a2;
    hepatizon::security::ZeroAllocator<float> a3;

    EXPECT_TRUE(a1 == a2);
    EXPECT_TRUE(a1 == a3);
    EXPECT_FALSE(a1 != a2);
}

TEST(ZeroAllocatorTests, AllocateZeroReturnsNull)
{
    hepatizon::security::ZeroAllocator<int> alloc;
    int* ptr = alloc.allocate(0);
    EXPECT_EQ(ptr, nullptr);
}

TEST(ZeroAllocatorTests, AllocateTooLargeThrows)
{
    hepatizon::security::ZeroAllocator<int> alloc;
    std::size_t impossibleSize = std::numeric_limits<std::size_t>::max();

    EXPECT_THROW({ [[maybe_unused]] auto* ptr = alloc.allocate(impossibleSize); }, std::bad_array_new_length);
}

TEST(ZeroAllocatorTests, DeallocateNullDoesNotCrash)
{
    hepatizon::security::ZeroAllocator<int> alloc;
    alloc.deallocate(nullptr, 100);

    SUCCEED();
}

TEST(ZeroAllocatorTests, SupportsNonTrivialTypes)
{
    std::vector<std::string, hepatizon::security::ZeroAllocator<std::string>> vec;
    vec.emplace_back("secure");
    vec.emplace_back("data");
    EXPECT_EQ(vec.size(), 2);
}