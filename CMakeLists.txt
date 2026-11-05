

cmake_minimum_required(VERSION 3.20)

project(WoW243Core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_library(core
    src/crypto/SRP6.cpp
    src/common/Config.cpp
    src/common/Logger.cpp
    src/database/Database.cpp
)

target_include_directories(core PUBLIC src)

target_link_libraries(core PUBLIC
    OpenSSL::Crypto
    Boost::system
)

if(WIN32)
    target_compile_definitions(core PUBLIC
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

add_executable(AuthServer
    src/main/auth_main.cpp
    src/authserver/AuthServer.cpp
    src/authserver/LogonChallenge.cpp
)

target_link_libraries(AuthServer PRIVATE core)

add_executable(WorldServer
    src/main/world_main.cpp
    src/worldserver/WorldServer.cpp
)

target_link_libraries(WorldServer PRIVATE core)
