// Read an INI file into easy-to-access name/value pairs.

// inih and INIReader are released under the New BSD license (see LICENSE.txt).
// Go to the project home page for more info:
//
// https://github.com/benhoyt/inih

#include <set>
#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "../ini.h"
#include "INIReader.h"

using std::string;

INIReader::INIReader(string filename)
{
    _error = ini_parse(filename.c_str(), ValueHandler, this);
}

int INIReader::ParseError()
{
    return _error;
}

string INIReader::Get(string section, string name, string default_value)
{
    string key = MakeKey(section, name);
    return _values.count(key) ? _values[key] : default_value;
}

long INIReader::GetInteger(string section, string name, long default_value)
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    // This parses "1234" (decimal) and also "0x4D2" (hex)
    long n = strtol(value, &end, 0);
    return end > value ? n : default_value;
}

double INIReader::GetReal(string section, string name, double default_value)
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    double n = strtod(value, &end);
    return end > value ? n : default_value;
}

bool INIReader::GetBoolean(string section, string name, bool default_value)
{
    string valstr = Get(section, name, "");
    // Convert to lower case to make string comparisons case-insensitive
    std::transform(valstr.begin(), valstr.end(), valstr.begin(), ::tolower);
    if (valstr == "true" || valstr == "yes" || valstr == "on" || valstr == "1")
        return true;
    else if (valstr == "false" || valstr == "no" || valstr == "off" || valstr == "0")
        return false;
    else
        return default_value;
}

void INIReader::GetSections(std::set<string> &values)
{
    values.clear();
    for (std::map<string, string>::const_iterator i = _values.begin();
        i != _values.end(); i++) {
        values.insert(
            i->first.substr(0, i->first.find_first_of('='))
        );
    }
}

void INIReader::GetSection(string section, std::map<string, string> &values)
{
    string key_prefix = section;
    key_prefix += "=";

    size_t key_prefix_len = key_prefix.size();

    values.clear();
    for (std::map<string, string>::const_iterator i = _values.begin();
        i != _values.end(); i++) {
        if (i->first.compare(0, key_prefix_len, key_prefix)) continue;
        values[i->first.substr(i->first.find_first_of('=') + 1)] = i->second;
    }
}

string INIReader::MakeKey(string section, string name)
{
    string key = section + "=" + name;
    // Convert to lower case to make section/name lookups case-insensitive
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    return key;
}

int INIReader::ValueHandler(void* user, const char* section, const char* name,
                            const char* value)
{
    INIReader* reader = (INIReader*)user;
    string key = MakeKey(section, name);
    if (reader->_values[key].size() > 0)
        reader->_values[key] += "\n";
    reader->_values[key] += value;
    return 1;
}
