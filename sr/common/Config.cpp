
#pragma once

#include <string>
#include <unordered_map>

class Config
{
public:
    bool Load(const std::string& filename);

    std::string Get(
        const std::string& key,
        const std::string& fallback = ""
    ) const;

    int GetInt(
        const std::string& key,
        int fallback = 0
    ) const;

private:
    std::unordered_map<std::string, std::string> values;
};
