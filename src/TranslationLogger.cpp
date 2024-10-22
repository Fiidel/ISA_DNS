#include "TranslationLogger.h"

TranslationLogger::TranslationLogger(char* filename)
{
    this->translationFilename = filename;
    this->hashTable = hashTableInit();

    // erase the file
    std::ofstream translationFile(this->translationFilename, std::ios::trunc);
    translationFile.close();
}

TranslationLogger::~TranslationLogger()
{
    hashTableDestroy(this->hashTable);
}

void TranslationLogger::logTranslation(char* domainName, char* address)
{
    if (!hashTableTranslationFind(this->hashTable, domainName, address))
    {
        std::ofstream translationFile(this->translationFilename, std::ios::app);
        translationFile << domainName << " " << address << std::endl;
        translationFile.close();

        hashTableAddTranslation(this->hashTable, domainName, address);
    }
}