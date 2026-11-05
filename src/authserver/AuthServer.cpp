
#include "AuthServer.h"
#include "common/Logger.h"

bool AuthServer::Start(const std::string& configFile)
{
    Logger::Info("Starting WoW243 AuthServer...");

    if (!config.Load(configFile))
    {
        Logger::Error("Cannot load AuthServer configuration");
        return false;
    }

    if (!database.Connect(
        config.Get("Database.Host", "127.0.0.1"),
        config.Get("Database.User", "wow"),
        config.Get("Database.Password", ""),
        config.Get("Database.Name", "wow_auth"),
        config.GetInt("Database.Port", 3306)))
    {
        Logger::Error("Authentication database connection failed");
        return false;
    }

    Logger::Info("Authentication database connected");
    Logger::Info("AuthServer initialization complete");

    return true;
}
