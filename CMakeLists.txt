
cmake_minimum_required(VERSION 3.20)

project(WoW243Core VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MYSQL REQUIRED IMPORTED_TARGET mysqlclient)

add_library(core
    src/common/Config.cpp
    src/common/Logger.cpp
    src/database/Database.cpp
)

target_include_directories(core PUBLIC src)

target_link_libraries(core PUBLIC
    OpenSSL::Crypto
    Boost::system
    PkgConfig::MYSQL
)

add_executable(AuthServer
    src/main/auth_main.cpp
    src/authserver/AuthServer.cpp
    src/network/Socket.cpp
)

target_link_libraries(AuthServer PRIVATE core)

add_executable(WorldServer
    src/main/world_main.cpp
    src/worldserver/WorldServer.cpp
    src/network/Socket.cpp
)

target_link_libraries(WorldServer PRIVATE core)
