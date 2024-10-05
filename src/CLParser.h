#ifndef CLPARSER_H
#define CLPARSER_H

#include "Configuration.h"

class CLParser
{
public:
    int ParseClArgs(int argc, char** argv, Configuration *configuration);
};

#endif