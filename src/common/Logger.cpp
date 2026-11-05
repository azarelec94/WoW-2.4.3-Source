
#include "Logger.h"

#include <iostream>
#include <chrono>
#include <ctime>

namespace Logger
{
    void Info(const std::string& message)
    {
        std::cout << "[INFO] " << message << '\n';
    }

    void Error(const std::string& message)
    {
        std::cerr << "[ERROR] " << message << '\n';
    }
}
