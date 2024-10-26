#include "TranslationLogger.h"

/// @brief TranslationLogger constructor.
/// @param filename The filename to write DNS translations to.
/// Stores the filename to write to, clears the file and initializes its hash table to check for duplicate entries.
TranslationLogger::TranslationLogger(char* filename)
{
    this->translationFilename = filename;

    // erase the file
    std::ofstream translationFile(this->translationFilename, std::ios::trunc);
    translationFile.close();

    // initialize the hash table
    this->hashTable = hashTableInit();
}

/// @brief TranslationLogger destructor.
/// Deletes the hash table with all its entries.
TranslationLogger::~TranslationLogger()
{
    hashTableDestroy(this->hashTable);
}

/// @brief Checks for duplicate entries in the logger hashtable and logs unique translations to the logger file.
/// @param domainName The domain name of the concrete translation.
/// @param address The IP address of the concrete translation.
void TranslationLogger::logTranslation(char* domainName, char* address)
{
    if (!hashTableTranslationFind(this->hashTable, domainName, address))
    {
        // open the translations file in append mode, log entry and close the file
        std::ofstream translationFile(this->translationFilename, std::ios::app);
        translationFile << domainName << " " << address << std::endl;
        translationFile.close();

        // add the logged translation to the hash table for future duplicate checks
        hashTableAddTranslation(this->hashTable, domainName, address);
    }
}