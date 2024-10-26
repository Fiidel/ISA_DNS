/* author: Adam Helešic
*  xlogin: xheles06
*/

#ifndef PACKETCAPTUREUTILS_H
#define PACKETCAPTUREUTILS_H

#include <iostream>
#include <string.h>
#include <pcap.h>
#include "DomainNameLogger.h"

#define NAME_BUFFER_SIZE 1000
#define RECORD_BUFFER_SIZE 2000

void discernRRType(ushort rrtype, char* buffer);
void discernRRClass(ushort rrclass, char* buffer);
ushort extractNameOffset(const u_char* DnsSections, int packetIndex);
void extractName(int* packetIndex, const u_char* DnsSections, char* nameBuffer, DomainNameLogger* domainLogger);
void extractType(int* packetIndex, const u_char* DnsSections, char* typeBuffer);
void extractClass(int* packetIndex, const u_char* DnsSections, char* classBuffer);
void extractTtl(int* ttl, int* packetIndex, const u_char* DnsSections);
void extractDataLength(ushort* dataLength, int* packetIndex, const u_char* DnsSections);
void extractCommonRrInformation(int* packetIndex, const u_char* DnsSections, char* nameBuffer, char* typeBuffer, char* classBuffer, int* ttl, 
    ushort* dataLength, DomainNameLogger* domainLogger);
void printCommonRrInformation(char* nameBuffer, int ttl, char* classBuffer, char* typeBuffer);
void processRrData(int* packetIndex, ushort dataLength, const u_char* DnsSections, char* type, char* rrDataBuffer, DomainNameLogger* domainLogger);
void printRrData(char* rrDataBuffer);

#endif