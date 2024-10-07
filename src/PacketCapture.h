#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

class PacketCapture
{
public:
    PacketCapture();
    int OpenCaptureOnInterface(Configuration* configuration);
};

#endif