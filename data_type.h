#ifndef __DATA_TYPE_H__
#define __DATA_TYPE_H__

const int ETHERNET_TYPE_IPV4;
const int ETHERNET_TYPE_ARP;
const int PROTOCOL_ID_TCP;
const int PROTOCOL_ID_UDP;

typedef struct ethernet_struct{
	u_char dest_addr_mac[6];
	u_char src_addr_mac[6];
	int ethernet_type;
}ethernet_struct;

typedef struct ipv4_struct{
	u_char dest_ip_addr[4];
	u_char src_ip_addr[4];
	int protocol_id;
}ipv4_struct;

typedef struct tcp_struct{
	int dest_tcp_port;
	int src_tcp_port;
}tcp_struct;

#endif