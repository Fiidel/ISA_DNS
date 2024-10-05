#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <iostream>

class Configuration
{
public:
    static bool verbose;
    static std::string interface;
    static std::string pcapFile;
    static std::string domainsFile;
    static std::string translationsFile;
};

#endif