#include "DomainNameLogger.h"

/// @brief DomainNameLogger constructor.
/// @param filename The filename to write domain names to.
/// Stores the filename to write to, clears the file and initializes its hash table to check for duplicate entries.
DomainNameLogger::DomainNameLogger(char* filename)
{
    this->domainFilename = filename;

    // erase the file
    std::ofstream domainFile(this->domainFilename, std::ios::trunc);
    domainFile.close();

    // initialize the hash table
    this->hashTable = hashTableInit();
}

/// @brief DomainNameLogger destructor.
/// Deletes the hash table with all its entries.
DomainNameLogger::~DomainNameLogger()
{
    hashTableDestroy(this->hashTable);
}

/// @brief Checks for duplicate entries in the logger hashtable and logs unique domain names to the logger file.
/// @param domainName The concrete domain name to check against duplicate entries and log into the domains file.
void DomainNameLogger::logDomainName(char* domainName)
{
    if (!hashTableDomainNameFind(this->hashTable, domainName))
    {
        // open the domain name file in append mode, log entry and close the file
        std::ofstream domainFile(this->domainFilename, std::ios::app);
        domainFile << domainName << std::endl;
        domainFile.close();

        // add the logged domain name to the hash table for future duplicate checks
        hashTableAddDomainName(this->hashTable, domainName);
    }
}