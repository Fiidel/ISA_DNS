#include <iostream>
#include "CLParser.h"
#include "Configuration.h"

int main(int argc, char** argv)
{
    CLParser clParser;
    Configuration* configuration = new Configuration();
    int clParserSuccess = clParser.ParseClArgs(argc, argv, configuration);
    if (clParserSuccess != 0)
    {
        std::cerr << "Command Line Parsing Failure. Aborting." << std::endl;
    }

    delete configuration;
    return 0;
}