#ifndef __PRINT_PACKET_H__
#define __PRINT_PACKET_H__

#include <pcap/pcap.h>
#include "deEncapsulate.h"
#include "dumpcode.h"

void printPacketInfo(u_char *packet, int len);
void printEthernetInfo(const ethernet_struct *eth);
void printIpv4Info(const ipv4_struct *ip);
void printTcpInfo(const tcp_struct *tcp);
void printTcpData(const u_char * packet, int len);

#endif