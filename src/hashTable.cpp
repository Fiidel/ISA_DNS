#include <iostream>
#include <string.h>
#include "hashTable.h"

int hash(char* domainName)
{
    int sum = 0;
    for (int i = 0; domainName[i] != '\0'; i++)
    {
        sum += domainName[i];
    }
    return sum % HASH_T_CAPACITY;
}

domainRecord* hashTableInit()
{
    domainRecord* hashTable = new domainRecord[HASH_T_CAPACITY];

    for (int i = 0; i < HASH_T_CAPACITY; i++)
    {
        hashTable[i].domainName[0] = '\0';
        hashTable[i].next = NULL;
    }

    return hashTable;
}

bool hashTableFind(domainRecord* hashTable, char* domainName)
{
    int index = hash(domainName);
    domainRecord* record = &hashTable[index];
    
    // for the root entry
    if (hashTable[index].domainName[0] == '\0')
    {
        return false;
    }

    // for the linked list entries from the index root
    while (record != NULL)
    {
        if (strcmp(record->domainName, domainName) == 0)
        {
            return true;
        }
        record = record->next;
    }
    return false;
}

void hashTableAdd(domainRecord* hashTable, char* domainName)
{
    if (hashTableFind(hashTable, domainName))
    {
        return;
    }

    int index = hash(domainName);

    // if root entry is empty, put the domainName there
    if (hashTable[index].domainName[0] == '\0')
    {
        strcpy(hashTable[index].domainName, domainName);
    }
    // else go into the linked list and add it to the first null next pointer
    else
    {
        domainRecord* futureRecordPtr = &hashTable[index];
        while (futureRecordPtr->next != NULL)
        {
            futureRecordPtr = futureRecordPtr->next;
        }
        domainRecord* newRecord = new domainRecord;
        strcpy(newRecord->domainName, domainName);
        newRecord->next = NULL;
        futureRecordPtr->next = newRecord;
    }
}

void deleteRecords(domainRecord* record)
{
    if (record != NULL)
    {
        deleteRecords(record->next);
        delete record;
    }
}

void hashTableDestroy(domainRecord* hashTable)
{
    for (int i = 0; i < HASH_T_CAPACITY; i++)
    {
        deleteRecords(hashTable[i].next);
    }
    delete[] hashTable;
}
