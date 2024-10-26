/* author: Adam Helešic
*  xlogin: xheles06
*/

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <iostream>
#include "DomainNameLogger.h"
#include "TranslationLogger.h"

class Configuration
{
public:
    bool verbose;
    char* interface;
    char* pcapFile;
    char* domainsFile;
    char* translationsFile;
    DomainNameLogger* domainLogger;
    TranslationLogger* translationLogger;

    Configuration();
    ~Configuration();
    void initLoggers();
};

#endif