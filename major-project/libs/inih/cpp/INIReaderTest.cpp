// Example that shows simple usage of the INIReader class

#include <iostream>
#include "INIReader.h"

int main()
{
    INIReader reader("../examples/test.ini");

    if (reader.ParseError() < 0) {
        std::cout << "Can't load 'test.ini'\n";
        return 1;
    }
    std::cout << "Config loaded from 'test.ini': version="
              << reader.GetInteger("protocol", "version", -1) << ", name="
              << reader.Get("user", "name", "UNKNOWN") << ", email="
              << reader.Get("user", "email", "UNKNOWN") << ", pi="
              << reader.GetReal("user", "pi", -1) << ", active="
              << reader.GetBoolean("user", "active", true) << "\n";

    std::map<std::string, std::string> section_kvp;
    std::map<std::string, std::string>::const_iterator i;

    reader.GetSection("user", section_kvp);
    std::cout << "Entries found in [user]: " << section_kvp.size() << std::endl;

    for (i = section_kvp.begin(); i != section_kvp.end(); i++)
        std::cout << i->first << " = " << i->second << std::endl;

    return 0;
}
