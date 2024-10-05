#include <iostream>
#include "CLParser.h"

int main(int argc, char** argv)
{
    CLParser clParser;
    clParser.ParseClArgs(argc, argv);
    
    return 0;
}