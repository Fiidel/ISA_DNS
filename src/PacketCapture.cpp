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

void extractName(int* packetIndex, const u_char* DnsSections, char* sectionBuffer)
{
    int bufferIndex = 0;
    int domainNameIndex = 0;
    bool isCompressed = false;
    int dnsHeaderLength = 12; // used to correctly calculate offset for compressed domain names

    // check if the first byte is the full name or a pointer to the name
    if (DnsSections[*packetIndex] >= 0xC0)
    {
        isCompressed = true;

        // the last 14 bits are the offset for the dns payload where the name can be found
        ushort nameOffset = ntohs(*((ushort*) &DnsSections[*packetIndex]));
        nameOffset = nameOffset & 0b0011111111111111;
        
        // this function receives DnsSections, which is the payload without the header;
        // we need to account for the offset, as the 14bits are the offset from the start
        // of the whole DNS packet, which includes the DNS header
        domainNameIndex = nameOffset - dnsHeaderLength;
        
        // the offset pointer is stored in 2 bytes which we want to skip when we return fron this function
        *packetIndex += 2;
    }
    else
    {
        // if the name isn't compressed, the first byte is the start of the full domain name
        domainNameIndex = *packetIndex;
    }

    // read the domain names until the terminating null byte
    while (DnsSections[domainNameIndex] != '\0')
    {
        // the first byte denotes the length of the domain name
        int domainNameLength = DnsSections[domainNameIndex];
        domainNameIndex++;

        // the domain name
        for (int i = 0; i < domainNameLength; i++)
        {
            sectionBuffer[bufferIndex] = DnsSections[domainNameIndex];
            bufferIndex++;
            domainNameIndex++;
        }
        
        sectionBuffer[bufferIndex] = '.';
        bufferIndex++;

        // packetIndex needs to increase at the same rate as domainNameIndex if the domain name 
        // isn't compressed (= accessed via a pointer)
        if (!isCompressed)
        {
            *packetIndex = domainNameIndex;
        }
    }

    // set the last byte of the domain name buffer to a null byte
    sectionBuffer[bufferIndex] = '\0';
    
    // if the domain name isn't compressed, you also need to skip the terminating null byte that  
    // denotes the end of the domain name section in the packet so that upon return from this
    // function, the packetIndex can be used correctly
    if (!isCompressed)
    {
        (*packetIndex)++;
    }
}

void extractTypeAndClass(int* packetIndex, const u_char* DnsSections, char* typeBuffer, char* classBuffer)
{
    ushort rrtype = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    discernRRType(rrtype, typeBuffer);
    *packetIndex += 2;

    ushort rrclass = ntohs(*((ushort*) &DnsSections[*packetIndex]));
    discernRRClass(rrclass, classBuffer);
    *packetIndex += 2;
}

void extractTtl(int* ttl, int* packetIndex, const u_char* DnsSections)
{
    *ttl = ntohl(*((int*) &DnsSections[*packetIndex]));
    *packetIndex += 4;
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
        char sectionBuffer[300];
        char typeBuffer[10];
        char classBuffer[10];
        int ttl = 0;
        int packetIndex = 0;

        for (int questionNum = 0; questionNum < dnsHeader->numOfQuestions; questionNum++)
        {
            extractName(&packetIndex, DnsSections, sectionBuffer);
            extractTypeAndClass(&packetIndex, DnsSections, typeBuffer, classBuffer);

            // print the name, type and class
            std::cout << sectionBuffer 
                << " " << classBuffer
                << " " << typeBuffer 
                << std::endl;
        }

        // === divider ============================================================================
        std::cout << std::endl;
        
        std::cout << "[Answer Section]" << std::endl;
        // TODO: support for the various RR types like CNAME etc.
        // must be able to parse into text format and print - see verbose output examples in assignment
        for (int answerNum = 0; answerNum < dnsHeader->numOfAnswers; answerNum++)
        {
            extractName(&packetIndex, DnsSections, sectionBuffer);
            extractTypeAndClass(&packetIndex, DnsSections, typeBuffer, classBuffer);
            extractTtl(&ttl, &packetIndex, DnsSections);

            ushort dataLength = ntohs(*((ushort*) &DnsSections[packetIndex]));
            packetIndex += 2;

            // TODO: process data
            // skip data section for now
            packetIndex += dataLength;

            // print the name, type and class
            std::cout << sectionBuffer 
                << " " << std::to_string(ttl)
                << " " << classBuffer
                << " " << typeBuffer 
                << std::endl;
        }
        

        // << std::endl
        // << "[Authority Section]" << std::endl 
        // << "Placeholder"
        // << std::endl
        // << std::endl
        // << "[Additional Section]" << std::endl 
        // << "Placeholder"
        // << std::endl
        
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