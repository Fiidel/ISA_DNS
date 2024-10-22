#include "DomainNameLogger.h"

DomainNameLogger::DomainNameLogger(char* filename)
{
    this->domainFilename = filename;
    this->hashTable = hashTableInit();

    // erase a file
    std::ofstream domainFile(this->domainFilename, std::ios::trunc);
    domainFile.close();
}

DomainNameLogger::~DomainNameLogger()
{
    hashTableDestroy(this->hashTable);
}

void DomainNameLogger::logDomainName(char* domainName)
{
    if (!hashTableDomainNameFind(this->hashTable, domainName))
    {
        std::ofstream domainFile(this->domainFilename, std::ios::app);
        domainFile << domainName << std::endl;
        domainFile.close();

        hashTableAddDomainName(this->hashTable, domainName);
    }
}