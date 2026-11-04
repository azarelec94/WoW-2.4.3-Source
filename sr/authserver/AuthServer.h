
#pragma once

#include "common/Config.h"
#include "database/Database.h"

class AuthServer
{
public:
    bool Start(const std::string& configFile);

private:
    Config config;
    Database database;
};
