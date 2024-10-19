#ifndef HASHTABLE_H
#define HASHTABLE_H

#define HASH_T_CAPACITY 64
#define DOMAIN_BUFFER_SIZE 256

typedef struct domainRecord
{
    char domainName[DOMAIN_BUFFER_SIZE];
    struct domainRecord* next;
} domainRecord;

int hash(char* domainName);
domainRecord* hashTableInit();
void hashTableAdd(domainRecord* hashTable, char* domainName);
bool hashTableFind(domainRecord* hashTable, char* domainName);
void hashTableDestroy(domainRecord* hashTable);

#endif