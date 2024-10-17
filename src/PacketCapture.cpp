#include <iostream>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "Configuration.h"
#include "PacketCapture.h"

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

ushort extractNameOffset(const u_char* DnsSections, int packetIndex)
{
    // the last 14 bits are the offset for the dns payload where the name can be found
    ushort nameOffset = ntohs(*((ushort*) &DnsSections[packetIndex]));
    nameOffset = nameOffset & 0b0011111111111111;
    return nameOffset;
}

void extractName(int* packetIndex, const u_char* DnsSections, char* sectionBuffer)
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
        strcpy(sectionBuffer, "<Root>");
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
            sectionBuffer[bufferIndex] = DnsSections[domainNameIndex];
            bufferIndex++;
            domainNameIndex++;
        }
        
        sectionBuffer[bufferIndex] = '.';
        bufferIndex++;
    }

    // set the last byte of the domain name buffer to a null byte
    sectionBuffer[bufferIndex] = '\0';
    
    // you also need to skip the terminating null byte that denotes the end of the domain name section
    // in the packet so that upon return from this function, the packetIndex can be used correctly
    (*packetIndex)++;
}

void extractType(int* packetIndex, const u_char* DnsSections, char* typeBuffer)
{
    ushort rrtype = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    discernRRType(rrtype, typeBuffer);
    *packetIndex += 2;
}

void extractClass(int* packetIndex, const u_char* DnsSections, char* classBuffer)
{
    ushort rrclass = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    discernRRClass(rrclass, classBuffer);
    *packetIndex += 2;
}

void extractTtl(int* ttl, int* packetIndex, const u_char* DnsSections)
{
    *ttl = ntohl(*((int*) &DnsSections[*packetIndex]));
    *packetIndex += 4;
}

void extractDataLength(ushort* dataLength, int* packetIndex, const u_char* DnsSections)
{
    *dataLength = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    *packetIndex += 2;
}

void extractCommonRrInformation(int* packetIndex, const u_char* DnsSections, char* sectionBuffer, char* typeBuffer, char* classBuffer, int* ttl, ushort* dataLength)
{
    extractName(packetIndex, DnsSections, sectionBuffer);
    extractType(packetIndex, DnsSections, typeBuffer);
    extractClass(packetIndex, DnsSections, classBuffer);
    extractTtl(ttl, packetIndex, DnsSections);
    extractDataLength(dataLength, packetIndex, DnsSections);
}

void printCommonRrInformation(char* sectionBuffer, int ttl, char* classBuffer, char* typeBuffer)
{
    // print the name, ttl, class and type
    std::cout << sectionBuffer 
        << " " << std::to_string(ttl)
        << " " << classBuffer
        << " " << typeBuffer;
}

void processRrData(int* packetIndex, ushort dataLength, const u_char* DnsSections, char* type, char* rrDataBuffer)
{
    if ((strcmp(type, "CNAME") == 0) || (strcmp(type, "NS") == 0))
    {
        // cant change the actual packetIndex as it will change at the end of the function, so use a substitute
        int proxyPacketIndex = *packetIndex;
        extractName(&proxyPacketIndex, DnsSections, rrDataBuffer);

        std::cout << " " << rrDataBuffer;
    }
    else if (strcmp(type, "A") == 0)
    {
        char addressBuffer[100];
        struct in_addr ipv4 = *((in_addr*) &DnsSections[*packetIndex]);
        inet_ntop(AF_INET, &ipv4, addressBuffer, 100);
        std::cout << " " << addressBuffer;
    }
    else if (strcmp(type, "AAAA") == 0)
    {
        char addressBuffer[100];
        struct in6_addr ipv6 = *((in6_addr*) &DnsSections[*packetIndex]);
        inet_ntop(AF_INET6, &ipv6, addressBuffer, 100);
        std::cout << " " << addressBuffer;
    }
    else if (strcmp(type, "MX") == 0)
    {
        ushort priority = ntohs(*((ushort*) &DnsSections[*packetIndex]));
        int proxyPacketIndex = *packetIndex + 2;

        extractName(&proxyPacketIndex, DnsSections, rrDataBuffer);
        std::cout << " " << priority << " " << rrDataBuffer;
    }
    else if (strcmp(type, "SOA") == 0)
    {
        int proxyPacketIndex = *packetIndex;
        
        // MNAME
        extractName(&proxyPacketIndex, DnsSections, rrDataBuffer);
        std::cout << " " << rrDataBuffer;

        // RNAME
        extractName(&proxyPacketIndex, DnsSections, rrDataBuffer);
        std::cout << " " << rrDataBuffer;

        // SERIAL
        unsigned int serial = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;
        std::cout << " " << std::to_string(serial);

        // REFRESH
        int refresh = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;
        std::cout << " " << std::to_string(refresh);

        // RETRY
        int retry = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;
        std::cout << " " << std::to_string(retry);

        // EXPIRE
        int expire = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;
        std::cout << " " << std::to_string(expire);

        // MINIMUM
        unsigned int minimum = ntohl(*((int*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 4;
        std::cout << " " << std::to_string(minimum);
    }
    else if (strcmp(type, "SRV") == 0)
    {
        int proxyPacketIndex = *packetIndex;

        ushort priority = ntohs(*((ushort*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 2;

        ushort weight = ntohs(*((ushort*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 2;

        ushort port = ntohs(*((ushort*) &DnsSections[proxyPacketIndex]));
        proxyPacketIndex += 2;

        extractName(&proxyPacketIndex, DnsSections, rrDataBuffer);
        
        std::cout << " " << priority << " " << weight << " " << port << " " << rrDataBuffer;
    }

    *packetIndex += dataLength;
}

void InterruptHandler(int sig)
{
    std::cout << "Interrupt." << std::endl;
    // TODO: clean up
    exit(0);
}

PacketCapture::PacketCapture(Configuration* config)
{
    this->configuration = config;
    signal(SIGINT, InterruptHandler);
}

void packet_handler(u_char *userArg, const struct pcap_pkthdr *header, const u_char *packet)
{
    // recast the configuration from userArg back to Configuration*
    Configuration* configuration = (Configuration*) userArg;

    // set up IP address variables
    struct in_addr* ipv4Src = NULL;
    struct in_addr* ipv4Dst = NULL;
    struct in6_addr* ipv6Src = NULL;
    struct in6_addr* ipv6Dst = NULL;

    // datetime
    time_t timestamp = header->ts.tv_sec;
    struct tm* datetime = localtime(&timestamp);
    char datetimeOutput[100];
    strftime(datetimeOutput, 100, "%Y-%m-%d %H:%M:%S", datetime);

    // ethernet header is 14B
    ushort ethHeaderLength = 14;
    // IPv4 header is variable, IPv6 header is 40B
    // UDP header is 8B
    ushort udpHeaderLength = 8;
    
    // Determine the IP header length and protocol.
    ushort ipHeaderLength = 0;
    ushort ipVersion = packet[14] >> 4;
    char protocolBuffer[4];
    // if IPv4
    if (ipVersion == 4)
    {
        // IP header's TIL 4b field contains the length of the IP header as a number of 32b words in the header
        ipHeaderLength = (ushort) packet[ethHeaderLength] & 0b00001111;
        ipHeaderLength *= 4;

        ipv4Src = (in_addr*) &packet[ethHeaderLength + 12];
        ipv4Dst = (in_addr*) &packet[ethHeaderLength + 16];
        
        u_char protocol = packet[ethHeaderLength + 9];
        if (protocol == 6)
        {
            strcpy(protocolBuffer, "TCP");
        }
        else if (protocol == 17)
        {
            strcpy(protocolBuffer, "UDP");
        }
        else
        {
            strcpy(protocolBuffer, "");
        }
    }
    // if IPv6
    else if (ipVersion == 6)
    {
        ipHeaderLength = 40;

        ipv6Src = (in6_addr*) &packet[ethHeaderLength + 8];
        ipv6Dst = (in6_addr*) &packet[ethHeaderLength + 24];

        u_char protocol = packet[ethHeaderLength + 6];
        if (protocol == 6)
        {
            strcpy(protocolBuffer, "TCP");
        }
        else if (protocol == 17)
        {
            strcpy(protocolBuffer, "UDP");
        }
        else
        {
            strcpy(protocolBuffer, "");
        }
    }
    else
    {
        std::cerr << "IP version incorrect. Ignoring packet." << std::endl;
        return;
    }

    // UDP header
    ushort srcPort = ntohs(*((ushort*) &packet[ethHeaderLength + ipHeaderLength]));
    ushort dstPort = ntohs(*((ushort*) &packet[ethHeaderLength + ipHeaderLength + 2]));

    // DNS payload and length
    const u_char *DnsPayload = &packet[ethHeaderLength + ipHeaderLength + udpHeaderLength];
    ushort DnsPayloadLength = (ushort) (((packet[ethHeaderLength + ipHeaderLength + 4] << 8)
        + packet[ethHeaderLength + ipHeaderLength + 5]) 
        - udpHeaderLength);

    struct DnsHeader
    {
        ushort transactionId;
        ushort flags;
        ushort numOfQuestions;
        ushort numOfAnswers;
        ushort numOfAuthorityRRs;
        ushort numOfAdditionalRRs;
    };

    struct DnsHeader* dnsHeader = (struct DnsHeader*) DnsPayload;

    // question, answer, ... sections
    const u_char *DnsSections = &DnsPayload[12];
    ushort DnsSectionsLength = DnsPayloadLength - 12;

    // convert byte order
    dnsHeader->transactionId = ntohs(dnsHeader->transactionId);
    dnsHeader->flags = ntohs(dnsHeader->flags);
    dnsHeader->numOfQuestions = ntohs(dnsHeader->numOfQuestions);
    dnsHeader->numOfAnswers = ntohs(dnsHeader->numOfAnswers);
    dnsHeader->numOfAuthorityRRs = ntohs(dnsHeader->numOfAuthorityRRs);
    dnsHeader->numOfAdditionalRRs = ntohs(dnsHeader->numOfAdditionalRRs);

    // get ip addresses
    char srcAddressBuffer[100];
    char dstAddressBuffer[100];

    if (ipVersion == 4)
    {
        inet_ntop(AF_INET, ipv4Src, srcAddressBuffer, 100);
        inet_ntop(AF_INET, ipv4Dst, dstAddressBuffer, 100);
    }
    else if (ipVersion == 6)
    {
        inet_ntop(AF_INET6, ipv6Src, srcAddressBuffer, 100);
        inet_ntop(AF_INET6, ipv6Dst, dstAddressBuffer, 100);
    }

    // determine the type - query/response
    char typeQR = ((dnsHeader->flags & 0b1000000000000000) >> 15) ? 'R' : 'Q';

    // output
    if (configuration->verbose)
    {
        std::cout << "Timestamp: " << datetimeOutput << std::endl;
        std::cout << "SrcIP: " << srcAddressBuffer << std::endl;
        std::cout << "DstIP: " << dstAddressBuffer << std::endl;
        std::cout << "SrcPort: " << protocolBuffer << "/" << srcPort << std::endl;
        std::cout << "DstPort: " << protocolBuffer << "/" << dstPort << std::endl;
        std::cout << "Identifier: 0x" << std::hex << std::uppercase << dnsHeader->transactionId << std::nouppercase << std::dec << std::endl;
        std::cout << "Flags: "
            << "QR=" << ((dnsHeader->flags & 0b1000000000000000) >> 15) << ", "
            << "OPCODE=" << ((dnsHeader->flags & 0b0111100000000000) >> 11) << ", "
            << "AA=" << ((dnsHeader->flags & 0b0000010000000000) >> 10) << ", " 
            << "TC=" << ((dnsHeader->flags & 0b0000001000000000) >> 9) << ", " 
            << "RD=" << ((dnsHeader->flags & 0b0000000100000000) >> 8) << ", " 
            << "RA=" << ((dnsHeader->flags & 0b0000000010000000) >> 7) << ", " 
            << "AD=" << ((dnsHeader->flags & 0b0000000000100000) >> 5) << ", " 
            << "CD=" << ((dnsHeader->flags & 0b0000000000010000) >> 4) << ", " 
            << "RCODE=" << (dnsHeader->flags & 0b0000000000001111)
            << std::endl
            << std::endl
            << "[Question Section]" << std::endl;

        // buffer for answers, ...
        char sectionBuffer[1000];
        char rrDataBuffer[300];
        char typeBuffer[10];
        char classBuffer[10];
        int ttl = 0;
        ushort dataLength = 0;
        int packetIndex = 0;

        for (int questionNum = 0; questionNum < dnsHeader->numOfQuestions; questionNum++)
        {
            extractName(&packetIndex, DnsSections, sectionBuffer);
            extractType(&packetIndex, DnsSections, typeBuffer);
            extractClass(&packetIndex, DnsSections, classBuffer);

            // print the name, type and class
            std::cout << sectionBuffer 
                << " " << classBuffer
                << " " << typeBuffer 
                << std::endl;
        }

        // === divider ============================================================================
        std::cout << std::endl;
        
        std::cout << "[Answer Section]" << std::endl;
        for (int answerNum = 0; answerNum < dnsHeader->numOfAnswers; answerNum++)
        {
            extractCommonRrInformation(&packetIndex, DnsSections, sectionBuffer, typeBuffer, classBuffer, &ttl, &dataLength);
            printCommonRrInformation(sectionBuffer, ttl, classBuffer, typeBuffer);

            processRrData(&packetIndex, dataLength, DnsSections, typeBuffer, rrDataBuffer);
            
            std::cout << std::endl;
        }
        
        // === divider ============================================================================
        std::cout << std::endl;
        
        std::cout << "[Authority Section]" << std::endl;
        for (int authorityNum = 0; authorityNum < dnsHeader->numOfAuthorityRRs; authorityNum++)
        {
            extractCommonRrInformation(&packetIndex, DnsSections, sectionBuffer, typeBuffer, classBuffer, &ttl, &dataLength);
            printCommonRrInformation(sectionBuffer, ttl, classBuffer, typeBuffer);

            processRrData(&packetIndex, dataLength, DnsSections, typeBuffer, rrDataBuffer);
            
            std::cout << std::endl;
        }

        // === divider ============================================================================
        std::cout << std::endl;
        
        std::cout<< "[Additional Section]" << std::endl;
        for (int additionalNum = 0; additionalNum < dnsHeader->numOfAdditionalRRs; additionalNum++)
        {
            // OPT type can be ignored as per the assignment (OPT breaks the record format and would require a new parsing function)

            // we do not want to update the packetIndex yet in case the record is OPT so we use a proxy
            int proxyPacketIndex = packetIndex;
            extractName(&proxyPacketIndex, DnsSections, sectionBuffer);
            extractType(&proxyPacketIndex, DnsSections, typeBuffer);

            if (strcmp(typeBuffer, "OPT") != 0)
            {
                extractCommonRrInformation(&packetIndex, DnsSections, sectionBuffer, typeBuffer, classBuffer, &ttl, &dataLength);
                printCommonRrInformation(sectionBuffer, ttl, classBuffer, typeBuffer);

                processRrData(&packetIndex, dataLength, DnsSections, typeBuffer, rrDataBuffer);
                
                std::cout << std::endl;   
            }
        }

        std::cout << "====================" << std::endl;
    }
    else
    {
        std::cout << datetimeOutput << " " << srcAddressBuffer << " -> " << dstAddressBuffer 
        << " (" << typeQR << " " 
        << dnsHeader->numOfQuestions << "/" << dnsHeader->numOfAnswers << "/" 
        << dnsHeader->numOfAuthorityRRs << "/" << dnsHeader->numOfAdditionalRRs << ")" 
        << std::endl;
    }

    return;
}

int PacketCapture::OpenCaptureOnInterface()
{
    pcap_t* handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    // ======================================================
    // IF INTERFACE CHOSEN

    if (configuration->interface != NULL)
    {
        // Find the specified interface in known devices.
        pcap_if_t* desiredDevice = NULL;
        pcap_if_t* devices = NULL;
        pcap_findalldevs(&devices, errbuf);

        if (devices == NULL)
        {
            std::cerr << "Error ocurred. No devices found." << std::endl;
            std::cerr << errbuf << std::endl;
            return 1;
        }

        for (pcap_if_t* device = devices; device != NULL; device = device->next)
        {
            if (strcmp(device->name, configuration->interface) == 0)
            {
                desiredDevice = device;
                break;
            }
        }

        if (desiredDevice == NULL)
        {
            std::cerr << "Specified interface not found." << std::endl;
            std::cerr << errbuf << std::endl;
            pcap_freealldevs(devices);
            return 1;
        }

        // Open packet capture.
        handle = pcap_open_live(desiredDevice->name, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL)
        {
            std::cerr << "Error opening live packet capture." << std::endl;
            std::cerr << errbuf << std::endl;
            pcap_freealldevs(devices);
            return 1;
        }

        pcap_freealldevs(devices);
    }

    // ======================================================
    // IF PCAP FILE CHOSEN

    if (configuration->pcapFile != NULL)
    {
        handle = pcap_open_offline(configuration->pcapFile, errbuf);

        if (handle == NULL)
        {
            std::cerr << "Error opening packet capture file." << std::endl;
            std::cerr << errbuf << std::endl;
            return 1;
        }
    }

    // Set filter.
    bpf_program filter;
    int compileSuccess = pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN);
    if (compileSuccess != 0)
    {
        std::cerr << "Error compiling filter." << std::endl;
        std::cerr << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    int filterSuccess = pcap_setfilter(handle, &filter);
    if (filterSuccess != 0)
    {
        std::cerr << "Error setting filter." << std::endl;
        std::cerr << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    // Loop over packets.
    pcap_loop(handle, -1, packet_handler, (u_char*) this->configuration);

    // Cleanup.
    pcap_close(handle);

    return 0;
}