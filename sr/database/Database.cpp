
#include "Database.h"
#include <iostream>

Database::Database()
    : connection(mysql_init(nullptr))
{
}

Database::~Database()
{
    Disconnect();
}

bool Database::Connect(
    const std::string& host,
    const std::string& user,
    const std::string& password,
    const std::string& database,
    unsigned int port)
{
    if (!connection)
        return false;

    if (!mysql_real_connect(
        connection,
        host.c_str(),
        user.c_str(),
        password.c_str(),
        database.c_str(),
        port,
        nullptr,
        0))
    {
        std::cerr << mysql_error(connection) << '\n';
        return false;
    }

    return true;
}

void Database::Disconnect()
{
    if (connection)
    {
        mysql_close(connection);
        connection = nullptr;
    }
}

bool Database::IsConnected() const
{
    return connection && mysql_ping(connection) == 0;
}
