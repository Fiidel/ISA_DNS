#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

class PacketCapture
{
public:
    PacketCapture(Configuration* config);
    Configuration* configuration;
    int OpenCaptureOnInterface();
};

#endif