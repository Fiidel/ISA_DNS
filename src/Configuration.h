#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <iostream>
#include "DomainNameLogger.h"

class Configuration
{
public:
    bool verbose;
    char* interface;
    char* pcapFile;
    char* domainsFile;
    char* translationsFile;
    DomainNameLogger* logger;

    Configuration();
    ~Configuration();
    void initLogger();
};

#endif