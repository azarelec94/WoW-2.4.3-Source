

cmake_minimum_required(VERSION 3.24)

project(WoW243Core
    VERSION 0.1.0
    DESCRIPTION "Independent World of Warcraft The Burning Crusade 2.4.3 emulator"
    LANGUAGES CXX
)

# ============================================================
# CONFIGURACION GENERAL
# ============================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WOW243_BUILD_AUTHSERVER "Build AuthServer" ON)
option(WOW243_BUILD_WORLDSERVER "Build WorldServer" ON)
option(WOW243_ENABLE_TESTS "Build unit tests" OFF)

# Directorios de salida
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/bin"
)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/lib"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/lib"
)

# ============================================================
# DEPENDENCIAS
# ============================================================

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

# ============================================================
# MYSQL 8 - MYSQL C API
# ============================================================

find_path(MYSQL_INCLUDE_DIR
    NAMES mysql.h
    PATH_SUFFIXES
        mysql
        mariadb
        mysql/include
)

find_library(MYSQL_CLIENT_LIBRARY
    NAMES
        mysqlclient
        libmysql
        mariadb
)

if(NOT MYSQL_INCLUDE_DIR)
    message(FATAL_ERROR
        "No se encontro mysql.h. Instala MySQL 8 Development Files."
    )
endif()

if(NOT MYSQL_CLIENT_LIBRARY)
    message(FATAL_ERROR
        "No se encontro la biblioteca cliente de MySQL."
    )
endif()

add_library(MySQLClient UNKNOWN IMPORTED)

set_target_properties(MySQLClient PROPERTIES
    IMPORTED_LOCATION "${MYSQL_CLIENT_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MYSQL_INCLUDE_DIR}"
)

# ============================================================
# OPCIONES DE COMPILACION
# ============================================================

if(MSVC)
    add_compile_options(
        /W4
        /permissive-
        /Zc:__cplusplus
        /EHsc
    )
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
    )
endif()

# ============================================================
# DIRECTORIOS DE INCLUSION
# ============================================================

include_directories(
    "${PROJECT_SOURCE_DIR}/src"
    "${MYSQL_INCLUDE_DIR}"
)

# ============================================================
# CODIGO COMPARTIDO
# ============================================================

file(GLOB_RECURSE WOW243_COMMON_SOURCES
    CONFIGURE_DEPENDS

    "${PROJECT_SOURCE_DIR}/src/common/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/crypto/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/database/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/network/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/protocol/*.cpp"
)

add_library(WoW243Common STATIC
    ${WOW243_COMMON_SOURCES}
)

target_include_directories(WoW243Common
    PUBLIC
        "${PROJECT_SOURCE_DIR}/src"
        "${MYSQL_INCLUDE_DIR}"
)

target_link_libraries(WoW243Common
    PUBLIC
        OpenSSL::Crypto
        OpenSSL::SSL
        Boost::system
        MySQLClient
)

# ============================================================
# AUTHSERVER
# ============================================================

if(WOW243_BUILD_AUTHSERVER)

    file(GLOB_RECURSE WOW243_AUTH_SOURCES
        CONFIGURE_DEPENDS

        "${PROJECT_SOURCE_DIR}/src/authserver/*.cpp"
    )

    set(AUTHSERVER_MAIN
        "${PROJECT_SOURCE_DIR}/src/main/AuthMain.cpp"
    )

    if(NOT EXISTS "${AUTHSERVER_MAIN}")
        message(FATAL_ERROR
            "Falta src/main/AuthMain.cpp"
        )
    endif()

    add_executable(AuthServer
        ${AUTHSERVER_MAIN}
        ${WOW243_AUTH_SOURCES}
    )

    target_link_libraries(AuthServer
        PRIVATE
            WoW243Common
    )

    target_include_directories(AuthServer
        PRIVATE
            "${PROJECT_SOURCE_DIR}/src"
    )

    set_target_properties(AuthServer PROPERTIES
        OUTPUT_NAME "AuthServer"
    )

endif()

# ============================================================
# WORLDSERVER
# ============================================================

if(WOW243_BUILD_WORLDSERVER)

    file(GLOB_RECURSE WOW243_WORLD_SOURCES
        CONFIGURE_DEPENDS

        "${PROJECT_SOURCE_DIR}/src/worldserver/*.cpp"
    )

    set(WORLDSERVER_MAIN
        "${PROJECT_SOURCE_DIR}/src/main/WorldMain.cpp"
    )

    if(NOT EXISTS "${WORLDSERVER_MAIN}")
        message(FATAL_ERROR
            "Falta src/main/WorldMain.cpp"
        )
    endif()

    add_executable(WorldServer
        ${WORLDSERVER_MAIN}
        ${WOW243_WORLD_SOURCES}
    )

    target_link_libraries(WorldServer
        PRIVATE
            WoW243Common
    )

    target_include_directories(WorldServer
        PRIVATE
            "${PROJECT_SOURCE_DIR}/src"
    )

    set_target_properties(WorldServer PROPERTIES
        OUTPUT_NAME "WorldServer"
    )

endif()

# ============================================================
# PRUEBAS
# ============================================================

if(WOW243_ENABLE_TESTS)

    enable_testing()

    if(EXISTS "${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt")
        add_subdirectory(tests)
    else()
        message(WARNING
            "WOW243_ENABLE_TESTS esta activado, pero no existe tests/CMakeLists.txt"
        )
    endif()

endif()

# ============================================================
# INFORMACION DE CONFIGURACION
# ============================================================

message(STATUS "==========================================")
message(STATUS " WoW243Core ${PROJECT_VERSION}")
message(STATUS "==========================================")
message(STATUS "C++ Standard: C++20")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "Boost: ${Boost_VERSION}")
message(STATUS "MySQL include: ${MYSQL_INCLUDE_DIR}")
message(STATUS "MySQL library: ${MYSQL_CLIENT_LIBRARY}")
message(STATUS "AuthServer: ${WOW243_BUILD_AUTHSERVER}")
message(STATUS "WorldServer: ${WOW243_BUILD_WORLDSERVER}")
message(STATUS "Tests: ${WOW243_ENABLE_TESTS}")
message(STATUS "==========================================")
