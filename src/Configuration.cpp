#include "Configuration.h"

/// @brief Configuration constructor.
Configuration::Configuration()
{
    verbose = false;
    interface = NULL;
    pcapFile = NULL;
    domainsFile = NULL;
    translationsFile = NULL;
}

/// @brief Configuration destructor.
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

/// @brief Constructor initializer. Creates loggers if files were specified in program arguments.
/// Needs to be called after the program arguments have been parsed and stored in the Configuration object.
/// Hence why it isn't a part of the Configuration constructor.
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