
#pragma once

#include <mysql.h>
#include <string>

class Database
{
public:
    Database();
    ~Database();

    bool Connect(
        const std::string& host,
        const std::string& user,
        const std::string& password,
        const std::string& database,
        unsigned int port
    );

    void Disconnect();
    bool IsConnected() const;

private:
    MYSQL* connection;
};
