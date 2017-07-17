#ifndef __DEENCAPSULATE_H__
#define __DEENCAPSULATE_H__

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>

#include "data_type.h"

void deEncapsulateEthernet(u_char *packet, ethernet_struct *eth);
void deEncapsulateIpv4(u_char *packet, ipv4_struct *ip);
void deEncapsulateTcp(u_char *packet, tcp_struct *tcp);
void deEncapsulateTcpData(u_char *packet);

#endif