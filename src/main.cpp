#include <iostream>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include "CLParser.h"
#include "Configuration.h"

void Cleanup(Configuration* configuration)
{
    if (configuration)
    {
        delete configuration;
    }
}

void packet_handler(u_char *userArg, const struct pcap_pkthdr *header, const u_char *bytes)
{
    // TODO: packet work
    std::cout << "Packet in packet handler." << std::endl;
    return;
}

int main(int argc, char** argv)
{
    CLParser clParser;
    Configuration* configuration = new Configuration();
    int clParserSuccess = clParser.ParseClArgs(argc, argv, configuration);
    if (clParserSuccess != 0)
    {
        std::cerr << "Command line parsing failure. Aborting." << std::endl;
        Cleanup(configuration);
        return 1;
    }

    // Find the specified interface in known devices.
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* desiredDevice = NULL;
    pcap_if_t* devices = NULL;
    pcap_findalldevs(&devices, errbuf);

    if (devices == NULL)
    {
        std::cerr << "Error ocurred. No devices found." << std::endl;
        std::cerr << errbuf << std::endl;
        Cleanup(configuration);
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
        Cleanup(configuration);
        pcap_freealldevs(devices);
        return 1;
    }

    // Open packet capture.
    pcap_t *handle = pcap_open_live(desiredDevice->name, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL)
    {
        std::cerr << "Error opening packet capture." << std::endl;
        std::cerr << errbuf << std::endl;
        Cleanup(configuration);
        pcap_freealldevs(devices);
        return 1;
    }

    // Loop over packets.
    pcap_loop(handle, -1, packet_handler, NULL);

    Cleanup(configuration);
    return 0;
}