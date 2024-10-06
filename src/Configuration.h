#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <iostream>

class Configuration
{
public:
    static bool verbose;
    static char* interface;
    static char* pcapFile;
    static char* domainsFile;
    static char* translationsFile;
};

#endif