/* author: Adam Helešic
*  xlogin: xheles06
*/

#ifndef DOMAINNAMELOGGER_H
#define DOMAINNAMELOGGER_H

#include <iostream>
#include <fstream>
#include "hashTable.h"

class DomainNameLogger
{
public:
    DomainNameLogger(char* domainFilename);
    ~DomainNameLogger();
    void logDomainName(char* domainName);
private:
    char* domainFilename;
    domainRecord* hashTable;
};

#endif