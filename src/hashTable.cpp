#include "hashTable.h"

/// @brief Hash function to map domain name to a hash table index.
/// @param domainName The domain name used for the hash function.
/// @return An integer index for the hash table.
int hash(char* domainName)
{
    int sum = 0;
    for (int i = 0; domainName[i] != '\0'; i++)
    {
        sum += domainName[i];
    }
    return sum % HASH_T_CAPACITY;
}

/// @brief Initializes the hash table up to its capacity.
/// @return A pointer to the hash table.
domainRecord* hashTableInit()
{
    domainRecord* hashTable = new domainRecord[HASH_T_CAPACITY];

    for (int i = 0; i < HASH_T_CAPACITY; i++)
    {
        hashTable[i].domainName[0] = '\0';
        hashTable[i].address = NULL;
        hashTable[i].next = NULL;
    }

    return hashTable;
}

/// @brief Searches for a domain name in the hash table.
/// @param hashTable The hash table to search.
/// @param domainName The domain name to search for.
/// @return True if the domain name is found, false otherwise.
bool hashTableDomainNameFind(domainRecord* hashTable, char* domainName)
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
        // domain names match
        if (strcmp(record->domainName, domainName) == 0)
        {
            return true;
        }
        record = record->next;
    }
    return false;
}

/// @brief Checks if an address of a record matches a given address.
/// @param record The record that stored the address.
/// @param address The address string to check.
/// @return True if the address matches, false otherwise.
bool doesRecordAddressMatch(domainRecord* record, char* address)
{
    return (strcmp(record->address, address) == 0);
}

/// @brief Checks every address of the hash table linked list records.
/// @param record The first record in the linked list.
/// @param address The address string to check.
/// @return True if a matching address is found, false otherwise.
bool checkAddressMatchOnIndex(domainRecord* record, char* address)
{
    while (record != NULL)
    {
        if (doesRecordAddressMatch(record, address))
        {
            return true;
        }
        record = record->next;
    }
    return false;
}

/// @brief Searches for a matching DNS translation in the hash table.
/// @param hashTable The hash table to search.
/// @param domainName The domain name of the translation.
/// @param address The IP address of the translation.
/// @return True if a matching translation is found, false otherwise.
bool hashTableTranslationFind(domainRecord* hashTable, char* domainName, char* address)
{
    int index = hash(domainName);
    
    if (hashTableDomainNameFind(hashTable, domainName))
    {
        if (checkAddressMatchOnIndex(&hashTable[index], address))
        {
            return true;
        }
    }
    return false;
}

/// @brief Adds a domain name to the hash table if it is not already stored.
/// @param hashTable The hash table to add the domain name to.
/// @param domainName The domain name to store.
void hashTableAddDomainName(domainRecord* hashTable, char* domainName)
{
    int index = hash(domainName);

    // skip if the domainName is already stored
    if (hashTableDomainNameFind(hashTable, domainName))
    {
        return;
    }

    // if root entry is empty (= domain name has not been stored yet), store the domainName there
    if (hashTable[index].domainName[0] == '\0')
    {
        domainRecord* record = &hashTable[index];

        strcpy(record->domainName, domainName);
    }
    // else go through the linked list and store it in the first null next pointer
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
        newRecord->address = NULL;
        
        futureRecordPtr->next = newRecord;
    }
}

/// @brief Adds a translation to the hash table if it is not already stored.
/// @param hashTable The hash table to add the translation to.
/// @param domainName The domain name of the translation to store.
/// @param address The IP address of the translation to store.
void hashTableAddTranslation(domainRecord* hashTable, char* domainName, char* address)
{
    int index = hash(domainName);

    // skip if the domainName and the same address is already stored
    // (the address needs to be checked because the name could be resolved to a different server for stuff like facebook etc.)
    if (hashTableDomainNameFind(hashTable, domainName))
    {
        if (checkAddressMatchOnIndex(&hashTable[index], address))
        {
            return;
        }
    }

    // if root entry is empty (= domain name has not been stored yet), store the domainName and address there
    if (hashTable[index].domainName[0] == '\0')
    {
        domainRecord* record = &hashTable[index];

        strcpy(record->domainName, domainName);

        record->address = new char[ADDRESS_BUFFER_SIZE];
        strcpy(record->address, address);

        record->next = NULL;
    }
    // else go through the linked list and store it in the first null next pointer
    else
    {
        domainRecord* futureRecordPtr = &hashTable[index];

        while (futureRecordPtr->next != NULL)
        {
            futureRecordPtr = futureRecordPtr->next;
        }

        domainRecord* newRecord = new domainRecord;

        strcpy(newRecord->domainName, domainName);

        newRecord->address = new char[ADDRESS_BUFFER_SIZE];
        strcpy(newRecord->address, address);

        newRecord->next = NULL;
        
        futureRecordPtr->next = newRecord;
    }
}

/// @brief Deletes all linked list records.
/// @param record The first record in the linked list.
void deleteRecords(domainRecord* record)
{
    if (record != NULL)
    {
        deleteRecords(record->next);
        if (record->address != NULL)
        {
            delete[] record->address;
        }
        delete record;
    }
}

/// @brief Deletes all records associated with the hash table and the hash table itself.
/// @param hashTable The hash table to delete.
void hashTableDestroy(domainRecord* hashTable)
{
    for (int i = 0; i < HASH_T_CAPACITY; i++)
    {
        // delete linked list records
        deleteRecords(hashTable[i].next);

        // delete allocated addresses if necessary
        if (hashTable[i].address != NULL)
        {
            delete[] hashTable[i].address;
        }
    }
    delete[] hashTable;
}
