#include <iostream>
#include <string.h>
#include <pcap.h>
#include "CLParser.h"
#include "Configuration.h"
#include "PacketCapture.h"

void Cleanup(Configuration* configuration)
{
    if (configuration)
    {
        delete configuration;
    }
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

    PacketCapture packetCapture;
    int pcapSuccess = packetCapture.OpenCaptureOnInterface(configuration);
    if (pcapSuccess != 0)
    {
        std::cerr << "PacketCapture error." << std::endl;
        Cleanup(configuration);
        return 1;
    }

    Cleanup(configuration);
    return 0;
}