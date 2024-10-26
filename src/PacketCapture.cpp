/* author: Adam Helešic
*  xlogin: xheles06
*/

#include <iostream>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "Configuration.h"
#include "PacketCapture.h"
#include "PacketCaptureUtils.h"
#include "DomainNameLogger.h"

// global configuration reference for cleanup on interrupt
Configuration* configGlobal = NULL;

/// @brief Cleans up allocated objects.
void CleanUp()
{
    if (configGlobal)
    {
        delete configGlobal;
    }
}

/// @brief Handles program interrupts, aborts, etc.
/// @param sig The signal that calls the handler.
void InterruptHandler(int sig)
{
    CleanUp();
    exit(0);
}

/// @brief The PacketCapture constructor.
/// @param config The Configuration of the packet capture.
PacketCapture::PacketCapture(Configuration* config)
{
    // store the configuration
    this->configuration = config;

    // store the configuration in the global variable for cleanup
    configGlobal = this->configuration;

    // link the possible program quitting signals to the handler
    signal(SIGINT, InterruptHandler);
    signal(SIGTERM, InterruptHandler);
    signal(SIGQUIT, InterruptHandler);
}

/// @brief Processes every packet from the pcap_loop.
/// @param userArg Possible user arguments (used to pass the Configuration).
/// @param header The header of the packet.
/// @param packet The whole packet.
void packet_handler(u_char *userArg, const struct pcap_pkthdr *header, const u_char *packet)
{
    // recast the configuration from userArg back to Configuration*
    Configuration* configuration = (Configuration*) userArg;

    // instantiate loggers or set to null
    DomainNameLogger* domainLogger = configuration->domainLogger;
    TranslationLogger* translationLogger = configuration->translationLogger;

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
    // ushort DnsPayloadLength = (ushort) (((packet[ethHeaderLength + ipHeaderLength + 4] << 8)
    //     + packet[ethHeaderLength + ipHeaderLength + 5]) 
    //     - udpHeaderLength);

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
    // ushort DnsSectionsLength = DnsPayloadLength - 12;

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
    if (!configuration->verbose)
    {
        std::cout << datetimeOutput << " " << srcAddressBuffer << " -> " << dstAddressBuffer 
        << " (" << typeQR << " " 
        << dnsHeader->numOfQuestions << "/" << dnsHeader->numOfAnswers << "/" 
        << dnsHeader->numOfAuthorityRRs << "/" << dnsHeader->numOfAdditionalRRs << ")" 
        << std::endl;
    }
    else
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
            << std::endl;
    }

    // === divider ============================================================================

    // buffers for questions, answers, ...
    char nameBuffer[NAME_BUFFER_SIZE];
    char rrDataBuffer[RECORD_BUFFER_SIZE];
    char typeBuffer[10];
    char classBuffer[10];
    int ttl = 0;
    ushort dataLength = 0;
    int packetIndex = 0;

    // QUESTIONS
    if (configuration->verbose)
    {
        std::cout << std::endl;
        std::cout << "[Question Section]" << std::endl;
    }

    for (int questionNum = 0; questionNum < dnsHeader->numOfQuestions; questionNum++)
    {
        extractName(&packetIndex, DnsSections, nameBuffer, domainLogger);
        extractType(&packetIndex, DnsSections, typeBuffer);
        extractClass(&packetIndex, DnsSections, classBuffer);

        if (configuration->verbose)
        {
            // print the name, type and class
            std::cout << nameBuffer << "."
                << " " << classBuffer
                << " " << typeBuffer 
                << std::endl;
        }
    }

    // === divider ============================================================================
    
    // ANSWERS
    if (configuration->verbose)
    {
        std::cout << std::endl;
        std::cout << "[Answer Section]" << std::endl;
    }
    
    for (int answerNum = 0; answerNum < dnsHeader->numOfAnswers; answerNum++)
    {
        extractCommonRrInformation(&packetIndex, DnsSections, nameBuffer, typeBuffer, classBuffer, &ttl, &dataLength, domainLogger);
        processRrData(&packetIndex, dataLength, DnsSections, typeBuffer, rrDataBuffer, domainLogger);

        if (configuration->verbose)
        {
            printCommonRrInformation(nameBuffer, ttl, classBuffer, typeBuffer);
            printRrData(rrDataBuffer);
            std::cout << std::endl;
        }

        if (strcmp(typeBuffer, "A") == 0 || strcmp(typeBuffer, "AAAA") == 0)
        {
            if (configuration->translationsFile != NULL)
            {
                translationLogger->logTranslation(nameBuffer, rrDataBuffer);
            }
        }
    }
    
    // === divider ============================================================================
    
    // AUTHORITY
    if (configuration->verbose)
    {
        std::cout << std::endl;
        std::cout << "[Authority Section]" << std::endl;
    }

    for (int authorityNum = 0; authorityNum < dnsHeader->numOfAuthorityRRs; authorityNum++)
    {
        extractCommonRrInformation(&packetIndex, DnsSections, nameBuffer, typeBuffer, classBuffer, &ttl, &dataLength, domainLogger);
        processRrData(&packetIndex, dataLength, DnsSections, typeBuffer, rrDataBuffer, domainLogger);
        
        if (configuration->verbose)
        {
            printCommonRrInformation(nameBuffer, ttl, classBuffer, typeBuffer);
            printRrData(rrDataBuffer);
            std::cout << std::endl;
        }
    }

    // === divider ============================================================================
    
    // ADDITIONAL
    if (configuration->verbose)
    {
        std::cout << std::endl;
        std::cout<< "[Additional Section]" << std::endl;
    }

    for (int additionalNum = 0; additionalNum < dnsHeader->numOfAdditionalRRs; additionalNum++)
    {
        // OPT type can be ignored as per the assignment (OPT breaks the record format and would require a new parsing function)

        // we do not want to update the packetIndex yet in case the record is OPT so we use a substitute
        int proxyPacketIndex = packetIndex;
        extractName(&proxyPacketIndex, DnsSections, nameBuffer, NULL); // purely so that the proxyPacketIndex increases by the domain name length and type can be accessed
        extractType(&proxyPacketIndex, DnsSections, typeBuffer);

        if (strcmp(typeBuffer, "OPT") != 0)
        {
            extractCommonRrInformation(&packetIndex, DnsSections, nameBuffer, typeBuffer, classBuffer, &ttl, &dataLength, domainLogger);
            processRrData(&packetIndex, dataLength, DnsSections, typeBuffer, rrDataBuffer, domainLogger);
            
            if (configuration->verbose)
            {
                printCommonRrInformation(nameBuffer, ttl, classBuffer, typeBuffer);
                printRrData(rrDataBuffer);
                std::cout << std::endl;
            }

            if (strcmp(typeBuffer, "A") == 0 || strcmp(typeBuffer, "AAAA") == 0)
            {
                if (configuration->translationsFile != NULL)
                {
                    translationLogger->logTranslation(nameBuffer, rrDataBuffer);
                }
            }
        }
    }

    // end divider
    if (configuration->verbose)
    {
        std::cout << "====================" << std::endl;
    }

    return;
}

/// @brief Opens capture on the specified interface or processes the specified pcap file.
/// @return 0 on success, 1 on failure.
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