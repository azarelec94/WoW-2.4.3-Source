
#include "Config.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

bool Config::Load(const std::string& filename)
{
    std::ifstream file(filename);

    if (!file.is_open())
        return false;

    std::string line;

    while (std::getline(file, line))
    {
        auto pos = line.find('=');

        if (pos == std::string::npos)
            continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        auto trim = [](std::string& s)
        {
            const auto first = s.find_first_not_of(" \t\r");
            if (first == std::string::npos)
            {
                s.clear();
                return;
            }

            const auto last = s.find_last_not_of(" \t\r");
            s = s.substr(first, last - first + 1);
        };

        trim(key);
        trim(value);

        if (!key.empty() && key[0] != '#')
            values[key] = value;
    }

    return true;
}

std::string Config::Get(
    const std::string& key,
    const std::string& fallback
) const
{
    auto it = values.find(key);

    return it != values.end() ? it->second : fallback;
}

int Config::GetInt(
    const std::string& key,
    int fallback
) const
{
    try
    {
        return std::stoi(Get(key));
    }
    catch (...)
    {
        return fallback;
    }
}
