#ifndef INCLUDE_HEPATIZON_STORAGE_SQLITE_SQLITESTORAGEREPOSITORYFACTORY_HPP
#define INCLUDE_HEPATIZON_STORAGE_SQLITE_SQLITESTORAGEREPOSITORYFACTORY_HPP

#include "hepatizon/storage/IStorageRepository.hpp"
#include <memory>

namespace hepatizon::storage::sqlite
{

[[nodiscard]] std::unique_ptr<hepatizon::storage::IStorageRepository> makeSqliteStorageRepository();

} // namespace hepatizon::storage::sqlite

#endif // INCLUDE_HEPATIZON_STORAGE_SQLITE_SQLITESTORAGEREPOSITORYFACTORY_HPP
