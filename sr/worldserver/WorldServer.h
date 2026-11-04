
#pragma once

#include "common/Config.h"
#include "database/Database.h"

class WorldServer
{
public:
    bool Start(const std::string& configFile);

private:
    Config config;
    Database database;
};
