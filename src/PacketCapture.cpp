#include <iostream>
#include <string.h>
#include <signal.h>
#include <pcap.h>
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

void packet_handler(u_char *userArg, const struct pcap_pkthdr *header, const u_char *bytes)
{
    // TODO: packet work
    std::cout << "Packet in packet handler." << std::endl;
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