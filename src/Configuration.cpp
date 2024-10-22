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
    if (domainLogger)
    {
        delete domainLogger;
    }

    if (translationLogger)
    {
        delete translationLogger;
    }
}

void Configuration::initLoggers()
{
    if (domainsFile == NULL)
    {
        domainLogger = NULL;
    }
    else
    {
        domainLogger = new DomainNameLogger(domainsFile);
    }

    if (translationsFile == NULL)
    {
        translationLogger = NULL;
    }
    else
    {
        translationLogger = new TranslationLogger(translationsFile);
    }
}