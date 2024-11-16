/* author: Adam Helešic
*  xlogin: xheles06
*/

#include <iostream>
#include <unistd.h>
#include <string.h>
#include "CLParser.h"

/// @brief Parses program arguments and stores them to a Configuration object.
/// @param argc Program argument count.
/// @param argv Array of program arguments.
/// @param configuration A Configuration object to store parsed arguments.
/// @return 0 on success, 1 on failure.
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
    while ((opt = getopt(argc, argv, "i:p:vd:t:h")) != -1)
    {
        switch (opt)
        {
            case 'i':
                configuration->interface = optarg;
                break;
            case 'p':
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

    // check if the specified file for pcap is .pcap
    if (configuration->pcapFile != NULL)
    {
        // first check length - otherwise could lead to an out of range exception
        if (strlen(configuration->pcapFile) <= 5)
        {
            std::cerr << "The specified pcap file doesn't have the .pcap extension." << std::endl;
            return 1;
        }

        // check if the last 5 characters are .pcap
        std::string pcapFile(configuration->pcapFile); // substr requires type string
        if (pcapFile.substr(pcapFile.length() - 5, pcapFile.length()) != ".pcap")
        {
            std::cerr << "The specified pcap file doesn't have the .pcap extension." << std::endl;
            return 1;
        }
    }

    // check if the .pcap file exists
    if (configuration->pcapFile != NULL)
    {
        if (access(configuration->pcapFile, F_OK) != 0)
        {
            std::cerr << "The specified pcap file was not found." << std::endl;
            return 1;
        }
    }

    // init domainLogger once the configuration is done
    configuration->initLoggers();

    // finished without errors
    return 0;
}