/* author: Adam Helešic
*  xlogin: xheles06
*/

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <iostream>
#include <string.h>

#define HASH_T_CAPACITY 64
#define DOMAIN_BUFFER_SIZE 1000
#define ADDRESS_BUFFER_SIZE 100

typedef struct domainRecord
{
    char domainName[DOMAIN_BUFFER_SIZE]; // domain name is always present in both types
    char* address; // address is only present in the address resolution type
    struct domainRecord* next;
} domainRecord;

int hash(char* domainName);
domainRecord* hashTableInit();
void hashTableAddDomainName(domainRecord* hashTable, char* domainName);
void hashTableAddTranslation(domainRecord* hashTable, char* domainName, char* address);
bool hashTableDomainNameFind(domainRecord* hashTable, char* domainName);
bool hashTableTranslationFind(domainRecord* hashTable, char* domainName, char* address);
void hashTableDestroy(domainRecord* hashTable);

#endif