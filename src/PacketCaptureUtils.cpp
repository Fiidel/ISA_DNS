/* author: Adam Helešic
*  xlogin: xheles06
*/

#include "PacketCaptureUtils.h"

/// @brief Fills a buffer with the name of the record type based on its value.
/// @param rrtype The record type value.
/// @param buffer The buffer for the record type name.
void discernRRType(ushort rrtype, char* buffer)
{
    switch (rrtype)
    {
        case 1:
            strcpy(buffer, "A");
            break;
        case 28:
            strcpy(buffer, "AAAA");
            break;
        case 2:
            strcpy(buffer, "NS");
            break;
        case 15:
            strcpy(buffer, "MX");
            break;
        case 6:
            strcpy(buffer, "SOA");
            break;
        case 5:
            strcpy(buffer, "CNAME");
            break;
        case 33:
            strcpy(buffer, "SRV");
            break;
        case 41:
            strcpy(buffer, "OPT");
            break;
        default:
            strcpy(buffer, "");
            break;
    }
}

/// @brief Fills a buffer with the name of the record class based on its value.
/// @param rrclass The record class value.
/// @param buffer The buffer for the record class name.
void discernRRClass(ushort rrclass, char* buffer)
{
    switch (rrclass)
    {
        case 1:
            strcpy(buffer, "IN");
            break;
        case 2:
            strcpy(buffer, "CS");
            break;
        case 3:
            strcpy(buffer, "CH");
            break;
        case 4:
            strcpy(buffer, "HS");
            break;
        default:
            strcpy(buffer, "");
            break;
    }
}

/// @brief Calculates the offset value (where to look for the domain name in the DNS payload) in case of compressed domain names.
/// @param DnsSections The DNS payload without the DNS header.
/// @param packetIndex The index of the compression byte in the DNS payload.
/// @return The offset for the DNS payload where the domain name/the next part of the domain name can be found.
ushort extractNameOffset(const u_char* DnsSections, int packetIndex)
{
    // the first 2 bits signify if the domain name is compressed
    // the last 14 bits are the offset for the dns payload where the name can be found
    ushort nameOffset = ntohs(*((ushort*) &DnsSections[packetIndex]));
    nameOffset = nameOffset & 0b0011111111111111;
    return nameOffset;
}

/// @brief Extracts the domain name from the DNS payload.
/// @param packetIndex The index of the first byte of the domain name in the DNS payload.
/// @param DnsSections The DNS payload without the DNS header.
/// @param nameBuffer The buffer where the domain name will be stored.
/// @param domainLogger The logger for logging domain names to an output file.
void extractName(int* packetIndex, const u_char* DnsSections, char* nameBuffer, DomainNameLogger* domainLogger)
{
    int bufferIndex = 0;
    int domainNameIndex = 0;
    bool trackPacketOffset = true; // true if the domain name isn't compressed
    int dnsHeaderLength = 12; // used to correctly calculate offset for compressed domain names

    // check if the first byte is the full name or a pointer to the name
    if (DnsSections[*packetIndex] >= 0xC0)
    {
        // turn off offset tracking
        trackPacketOffset = false;

        // get the offset and start index for the domain name parsing
        ushort nameOffset = extractNameOffset(DnsSections, *packetIndex);
        
        // this function receives DnsSections, which is the payload without the header;
        // we need to account for the offset, as the 14bits are the offset from the start
        // of the whole DNS packet, which includes the DNS header
        domainNameIndex = nameOffset - dnsHeaderLength;
        
        // the offset pointer is stored in 2 bytes which we want to skip when we return fron this function;
        // packetIndex is increased by 1 at the end of the function (see below), so we only add 1 here rather than 2
        *packetIndex += 1;
    }
    else if (DnsSections[*packetIndex] == '\0')
    {
        // root domain (empty string by definition)
        strcpy(nameBuffer, "");
        *packetIndex += 1;
        return;
    }
    else
    {
        // if the name isn't compressed, the first byte is the start of the full domain name
        domainNameIndex = *packetIndex;
    }

    // read the domain names until the terminating null byte
    while (DnsSections[domainNameIndex] != '\0')
    {
        // compressed names can have offset pointers too
        if (DnsSections[domainNameIndex] >= 0xC0)
        {
            trackPacketOffset = false;
            ushort nameOffset = extractNameOffset(DnsSections, domainNameIndex);
            domainNameIndex = nameOffset - dnsHeaderLength;
        }

        // the first byte denotes the length of the domain name
        int domainNameLength = DnsSections[domainNameIndex];

        // packetIndex needs to increase at the same rate as domainNameIndex if the domain name 
        // isn't compressed (= accessed via a pointer)
        if (trackPacketOffset)
        {
            // increase by 1 (for the byte denoting the length of the domain name) + the length of the domain name
            *packetIndex += 1 + domainNameLength;
        }

        // the domain name
        domainNameIndex++; // skips the byte that denotes the length of the domain name
        for (int i = 0; i < domainNameLength; i++)
        {
            nameBuffer[bufferIndex] = DnsSections[domainNameIndex];
            bufferIndex++;
            domainNameIndex++;
        }
        
        nameBuffer[bufferIndex] = '.';
        bufferIndex++;
    }

    // set the last byte of the domain name buffer to a null byte (replaces the end period, hence --bufferIndex)
    nameBuffer[--bufferIndex] = '\0';

    // if the domainLogger is defined, log the domain name
    if (domainLogger != NULL)
    {
        domainLogger->logDomainName(nameBuffer);
    }
    
    // you also need to skip the terminating null byte that denotes the end of the domain name section
    // in the packet so that upon return from this function, the packetIndex can be used correctly
    (*packetIndex)++;
}

/// @brief Extracts the record type value from the DNS payload.
/// @param packetIndex The index of the record type in the DNS payload.
/// @param DnsSections The DNS payload without the DNS header.
/// @param typeBuffer The buffer where the record type will be stored.
void extractType(int* packetIndex, const u_char* DnsSections, char* typeBuffer)
{
    ushort rrtype = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    discernRRType(rrtype, typeBuffer);
    *packetIndex += 2;
}

/// @brief Extracts the record class value from the DNS payload.
/// @param packetIndex The index of the record class in the DNS payload.
/// @param DnsSections The DNS payload without the DNS header.
/// @param classBuffer The buffer where the record class will be stored.
void extractClass(int* packetIndex, const u_char* DnsSections, char* classBuffer)
{
    ushort rrclass = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    discernRRClass(rrclass, classBuffer);
    *packetIndex += 2;
}

/// @brief Extracts TTL from the DNS payload.
/// @param ttl A pointer where the TTL will be stored.
/// @param packetIndex The index of the TTL in the DNS payload.
/// @param DnsSections The DNS payload without the DNS header.
void extractTtl(int* ttl, int* packetIndex, const u_char* DnsSections)
{
    *ttl = ntohl(*((int*) &DnsSections[*packetIndex]));
    *packetIndex += 4;
}

/// @brief Extracts the data length of a record from the DNS payload.
/// @param dataLength A pointer where the data length will be stored.
/// @param packetIndex The index of the data length in the DNS payload.
/// @param DnsSections The DNS payload without the DNS header.
void extractDataLength(ushort* dataLength, int* packetIndex, const u_char* DnsSections)
{
    *dataLength = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    *packetIndex += 2;
}

/// @brief Extracts record information common for all records.
/// @param packetIndex The starting index of the record in the DNS payload.
/// @param DnsSections The DNS payload without the DNS header.
/// @param nameBuffer A buffer for the domain name.
/// @param typeBuffer A buffer for the record type.
/// @param classBuffer A buffer for the record class.
/// @param ttl A pointer where the TTL will be stored.
/// @param dataLength The length of the record data.
/// @param domainLogger A logger to log the domain names.
void extractCommonRrInformation(int* packetIndex, const u_char* DnsSections, char* nameBuffer, char* typeBuffer, char* classBuffer, int* ttl, 
    ushort* dataLength, DomainNameLogger* domainLogger)
{
    extractName(packetIndex, DnsSections, nameBuffer, domainLogger);
    extractType(packetIndex, DnsSections, typeBuffer);
    extractClass(packetIndex, DnsSections, classBuffer);
    extractTtl(ttl, packetIndex, DnsSections);
    extractDataLength(dataLength, packetIndex, DnsSections);
}

/// @brief Prints the common record information.
/// @param nameBuffer The buffer with the domain name.
/// @param ttl The TTL value.
/// @param classBuffer The buffer with the record class.
/// @param typeBuffer The buffer with the record type.
void printCommonRrInformation(char* nameBuffer, int ttl, char* classBuffer, char* typeBuffer)
{
    // print the name, ttl, class and type
    std::cout << nameBuffer << "."
        << " " << std::to_string(ttl)
        << " " << classBuffer
        << " " << typeBuffer;
}

/// @brief Processes a whole record.
/// @param packetIndex The starting index of the record in the DNS payload.
/// @param dataLength The length of the record data.
/// @param DnsSections The DNS payload without the DNS header.
/// @param type The type of the record.
/// @param rrDataBuffer A buffer for the non-common data of the record.
/// @param domainLogger A logger to log the domain names.
void processRrData(int* packetIndex, ushort dataLength, const u_char* DnsSections, char* type, char* rrDataBuffer, DomainNameLogger* domainLogger)
{
    // clean the array
    memset(rrDataBuffer, 0, RECORD_BUFFER_SIZE);

    // behavior based on type
    if ((strcmp(type, "CNAME") == 0) || (strcmp(type, "NS") == 0))
    {
        // cant change the actual packetIndex as it will change at the end of the function, so use a substitute
        int proxyPacketIndex = *packetIndex;
        extractName(&proxyPacketIndex, DnsSections, rrDataBuffer, domainLogger);
    }
    else if (strcmp(type, "A") == 0)
    {
        char addressBuffer[RR_ADDRESS_BUFFER_SIZE];
        struct in_addr ipv4 = *((in_addr*) &DnsSections[*packetIndex]);
        inet_ntop(AF_INET, &ipv4, addressBuffer, RR_ADDRESS_BUFFER_SIZE);

        strcat(rrDataBuffer, addressBuffer);
    }
    else if (strcmp(type, "AAAA") == 0)
    {
        char addressBuffer[RR_ADDRESS_BUFFER_SIZE];
        struct in6_addr ipv6 = *((in6_addr*) &DnsSections[*packetIndex]);
        inet_ntop(AF_INET6, &ipv6, addressBuffer, RR_ADDRESS_BUFFER_SIZE);
        
        strcat(rrDataBuffer, addressBuffer);
    }
    else if (strcmp(type, "MX") == 0)
    {
        ushort priority = ntohs(*((ushort*) &DnsSections[*packetIndex]));
        int proxyPacketIndex = *packetIndex + 2;

        char tempBuffer[500];
        extractName(&proxyPacketIndex, DnsSections, tempBuffer, domainLogger);

        strcat(rrDataBuffer, std::to_string(priority).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, tempBuffer);
    }
    else if (strcmp(type, "SOA") == 0)
    {
        int proxyPacketIndex = *packetIndex;
        char mnameBuffer[RR_MNAME_RNAME_BUFFER_SIZE];
        memset(mnameBuffer, 0, RR_MNAME_RNAME_BUFFER_SIZE);
        char rnameBuffer[RR_MNAME_RNAME_BUFFER_SIZE];
        memset(rnameBuffer, 0, RR_MNAME_RNAME_BUFFER_SIZE);
        
        // MNAME
        extractName(&proxyPacketIndex, DnsSections, mnameBuffer, domainLogger);

        // RNAME
        extractName(&proxyPacketIndex, DnsSections, rnameBuffer, NULL);

        // SERIAL
        unsigned int serial = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;

        // REFRESH
        int refresh = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;

        // RETRY
        int retry = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;

        // EXPIRE
        int expire = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;

        // MINIMUM
        unsigned int minimum = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;

        // put data to output buffer
        strcat(rrDataBuffer, mnameBuffer);
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, rnameBuffer);
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(serial).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(refresh).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(retry).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(expire).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(minimum).c_str());
    }
    else if (strcmp(type, "SRV") == 0)
    {
        int proxyPacketIndex = *packetIndex;
        char tempBuffer[500];

        ushort priority = ntohs(*((ushort*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 2;

        ushort weight = ntohs(*((ushort*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 2;

        ushort port = ntohs(*((ushort*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 2;

        extractName(&proxyPacketIndex, DnsSections, tempBuffer, domainLogger);
        
        strcat(rrDataBuffer, std::to_string(priority).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(weight).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, std::to_string(port).c_str());
        strcat(rrDataBuffer, " ");
        strcat(rrDataBuffer, tempBuffer);
    }

    *packetIndex += dataLength;
}

/// @brief Prints record data from the provided buffer.
/// @param rrDataBuffer The buffer with the non-common record data.
void printRrData(char* rrDataBuffer)
{
    std::cout << " " << rrDataBuffer;
}
