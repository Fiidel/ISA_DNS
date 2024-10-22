#include <iostream>
#include <unistd.h>
#include "CLParser.h"

int CLParser::ParseClArgs(int argc, char** argv, Configuration *configuration)
{
    int opt;

    // no arguments
    if (argc == 1)
    {
        std::cout << "Invalid usage. Type ./dns-monitor -h for usage." << std::endl;
        return 1;
    }

    // parsing arguments
    while ((opt = getopt(argc, argv, "i:r:vd:t:h")) != -1)
    {
        switch (opt)
        {
            case 'i':
                configuration->interface = optarg;
                break;
            case 'r':
                configuration->pcapFile = optarg;
                break;
            case 'v':
                configuration->verbose = true;
                break;
            case 'd':
                configuration->domainsFile = optarg;
                break;
            case 't':
                configuration->translationsFile = optarg;
                break;
            case 'h':
                std::cout << "Usage: ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]" << std::endl;
                return 0;
            default:
                std::cout << "Invalid option(s). Type ./dns-monitor -h for usage." << std::endl;
                return 1;
        }
    }

    // check either interface or pcap file is specified (not both)
    if (configuration->interface != NULL && configuration->pcapFile != NULL)
    {
        std::cerr << "Please specify either an interface or a pcap file, not both." << std::endl;
        return 1;
    }

    // check either interface or pcap file is specified (at least one)
    if (configuration->interface == NULL && configuration->pcapFile == NULL)
    {
        std::cerr << "Please specify either an interface or a pcap file." << std::endl;
        return 1;
    }

    // init domainLogger if domain name file is specified
    configuration->initLoggers();

    // finished without errors
    return 0;
}