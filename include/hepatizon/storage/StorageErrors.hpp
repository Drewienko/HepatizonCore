#ifndef INCLUDE_HEPATIZON_STORAGE_STORAGEERRORS_HPP
#define INCLUDE_HEPATIZON_STORAGE_STORAGEERRORS_HPP

#include <stdexcept>

namespace hepatizon::storage
{

class VaultNotFound final : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

} // namespace hepatizon::storage

#endif // INCLUDE_HEPATIZON_STORAGE_STORAGEERRORS_HPP
