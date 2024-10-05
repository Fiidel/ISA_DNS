#include <iostream>
#include <unistd.h>
#include "CLParser.h"

int CLParser::ParseClArgs(int argc, char** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "i:r:vd:t:h")) != -1)
    {
        switch (opt)
        {
            case 'i':
                std::cout << "Detected i " << optarg << std::endl;
                break;
            case 'r':
                std::cout << "Detected r " << optarg << std::endl;
                break;
            case 'v':
                std::cout << "Detected v" << std::endl;
                break;
            case 'd':
                std::cout << "Detected d " << optarg << std::endl;
                break;
            case 't':
                std::cout << "Detected t " << optarg << std::endl;
                break;
            case 'h':
                std::cout << "This is help." << std::endl;
                break;
            default:
                std::cout << "Wrong switch. Type ./dns-monitor -h for usage." << std::endl;
                break;
        }
    }
    // finished without errors
    return 0;
}