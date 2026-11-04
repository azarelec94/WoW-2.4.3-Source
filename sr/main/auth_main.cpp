
#include "authserver/AuthServer.h"

int main()
{
    AuthServer server;

    return server.Start("config/authserver.conf")
        ? 0 : 1;
}
