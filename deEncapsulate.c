#include "deEncapsulate.h"

void deEncapsulateEthernet(u_char *packet, ethernet_struct *eth)
{
	memcpy(eth->dest_addr_mac, packet, 6);
	memcpy(eth->src_addr_mac, packet + 6, 6);
	eth->ethernet_type = (int)packet[12] * 0x100 + packet[13];
}

void deEncapsulateIpv4(u_char *packet, ipv4_struct *ip)
{
	packet += 14;
	ip->protocol_id = packet[9];
	memcpy(ip->src_ip_addr, packet + 12, 4);
	memcpy(ip->dest_ip_addr, packet + 16, 4);
}

void deEncapsulateTcp(u_char *packet, tcp_struct *tcp)
{
	packet += 34;

	tcp->src_tcp_port = packet[1] + packet[0] * 0x100;
	tcp->dest_tcp_port = packet[3] + packet[2] * 0x100;
}

void deEncapsulateTcpData(u_char *packet)
{
	packet += 20;
}

