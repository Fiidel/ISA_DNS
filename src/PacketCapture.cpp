#include <iostream>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "Configuration.h"
#include "PacketCapture.h"

void InterruptHandler(int sig)
{
    std::cout << "Interrupt." << std::endl;
    // TODO: clean up
    exit(0);
}

PacketCapture::PacketCapture()
{
    signal(SIGINT, InterruptHandler);
}

void packet_handler(u_char *userArg, const struct pcap_pkthdr *header, const u_char *packet)
{
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
    
    // Determine the IP header length.
    ushort ipHeaderLength = 0;
    ushort ipVersion = packet[14] >> 4;
    // if IPv4
    if (ipVersion == 4)
    {
        // IP header's TIL 4b field contains the length of the IP header as a number of 32b words in the header
        ipHeaderLength = (ushort) packet[ethHeaderLength] & 0b00001111;
        ipHeaderLength *= 4;

        ipv4Src = (in_addr*) &packet[ethHeaderLength + 12];
        ipv4Dst = (in_addr*) &packet[ethHeaderLength + 16];
    }
    // if IPv6
    else if (ipVersion == 6)
    {
        ipHeaderLength = 40;

        ipv6Src = (in6_addr*) &packet[ethHeaderLength + 8];
        ipv6Dst = (in6_addr*) &packet[ethHeaderLength + 24];
    }
    else
    {
        std::cerr << "IP version incorrect. Ignoring packet." << std::endl;
        return;
    }

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

    std::cout << datetimeOutput << " " << srcAddressBuffer << " -> " << dstAddressBuffer << std::endl;

    return;
}

int PacketCapture::OpenCaptureOnInterface(Configuration* configuration)
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
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup.
    pcap_close(handle);

    return 0;
}