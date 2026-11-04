
#include "worldserver/WorldServer.h"

int main()
{
    WorldServer server;

    return server.Start("config/worldserver.conf")
        ? 0 : 1;
}
