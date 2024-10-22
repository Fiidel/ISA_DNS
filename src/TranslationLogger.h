#ifndef TRANSLATIONLOGGER_H
#define TRANSLATIONLOGGER_H

#include <iostream>
#include <fstream>
#include "hashTable.h"

class TranslationLogger
{
public:
    TranslationLogger(char* translationFilename);
    ~TranslationLogger();
    void logTranslation(char* domainName, char* address);
private:
    char* translationFilename;
    domainRecord* hashTable;
};

#endif