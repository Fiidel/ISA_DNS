#include "Configuration.h"

Configuration::Configuration()
{
    verbose = false;
    interface = NULL;
    pcapFile = NULL;
    domainsFile = NULL;
    translationsFile = NULL;
}

Configuration::~Configuration()
{
    if (logger)
    {
        delete logger;
    }
}

void Configuration::initLogger()
{
    if (domainsFile == NULL)
    {
        logger = NULL;
    }
    else
    {
        logger = new DomainNameLogger(domainsFile);
    }
}