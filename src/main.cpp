/* author: Adam Helešic
*  xlogin: xheles06
*/

#include <iostream>
#include <string.h>
#include <pcap.h>
#include "CLParser.h"
#include "Configuration.h"
#include "PacketCapture.h"

/// @brief Deletes the allocated Configuration.
/// @param configuration A Configuration object to be deleted.
void Cleanup(Configuration* configuration)
{
    if (configuration)
    {
        delete configuration;
    }
}

int main(int argc, char** argv)
{
    // instantiate command line parser and configuration
    CLParser clParser;
    Configuration* configuration = new Configuration();

    // parse command line arguments and handle possible failures
    int clParserSuccess = clParser.ParseClArgs(argc, argv, configuration);
    if (clParserSuccess != 0)
    {
        std::cerr << "Command line parsing failure. Aborting." << std::endl;
        Cleanup(configuration);
        return 1;
    }

    // instantiate packet capture object with the configuration
    PacketCapture packetCapture(configuration);

    // open the capture/process a pcap file and handle possible failures
    int pcapSuccess = packetCapture.OpenCaptureOnInterface();
    if (pcapSuccess != 0)
    {
        std::cerr << "PacketCapture error." << std::endl;
        Cleanup(configuration);
        return 1;
    }

    // clean up at the end of the program
    Cleanup(configuration);
    return 0;
}