
#include "WorldServer.h"
#include "common/Logger.h"

bool WorldServer::Start(const std::string& configFile)
{
    Logger::Info("Starting WoW243 WorldServer...");

    if (!config.Load(configFile))
    {
        Logger::Error("Cannot load WorldServer configuration");
        return false;
    }

    if (!database.Connect(
        config.Get("Database.Host", "127.0.0.1"),
        config.Get("Database.User", "wow"),
        config.Get("Database.Password", ""),
        config.Get("Database.Name", "wow_world"),
        config.GetInt("Database.Port", 3306)))
    {
        Logger::Error("World database connection failed");
        return false;
    }

    Logger::Info("World database connected");
    Logger::Info("WorldServer initialization complete");

    return true;
}
