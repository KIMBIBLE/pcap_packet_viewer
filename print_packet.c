#include "print_packet.h"

void printPacketInfo(u_char *packet, int len)
{
	int e_type = 0;
	int protocol_id = 0;
	ethernet_struct ethernet;
	ipv4_struct ipv4;
	tcp_struct tcp;

	/*	Ethernet_header 	*/
	deEncapsulateEthernet(packet, &ethernet);

	if(ethernet.ethernet_type == ETHERNET_TYPE_IPV4)
		printEthernetInfo(&ethernet);
	else if(ethernet.ethernet_type == ETHERNET_TYPE_ARP){
		printf("arp packet\n");
		return;
	}
	else{
		printf("other packet : %02x\n", ethernet.ethernet_type);
		return;
	}
	
	/*	Ipv4_header 	*/
	deEncapsulateIpv4(packet, &ipv4);
	printIpv4Info(&ipv4);
	if(ipv4.protocol_id == PROTOCOL_ID_TCP){
		deEncapsulateTcp(packet, &tcp);
		printTcpInfo(&tcp);
	}
	else if(ipv4.protocol_id == PROTOCOL_ID_UDP){
		printf("udp packet\n");
		return;
	}
	else{
		printf("other packet : %02x\n", ipv4.protocol_id);
		return;
	}

	deEncapsulateTcpData(packet);
	printTcpData(packet, len);
}

void printEthernetInfo(const ethernet_struct *eth)
{
	int i;
	puts("");
	printf("[-]	[ethernet_header]\n");
	printf("[*]	destination\t: ");
	for(i = 0; i < 6; i++){
		printf("%02x", eth->dest_addr_mac[i]);
		if(i < 5)
			printf(":");
	}
	puts("");

	printf("[*]	source\t\t: ");
	for(i = 0; i < 6; i++){
		printf("%02x", eth->src_addr_mac[i]);
		if(i < 5)
			printf(":");
	}
	puts("");


}

void printIpv4Info(const ipv4_struct *ip)
{
	int i;
	puts("");
	printf("[-]	[ipv4_header]\n");

	printf("[*]	destination\t: ");
	for(i = 0; i < 4; i++){
		printf("%d", ip->dest_ip_addr[i]);
		if(i < 3)
			printf(".");
	}
	puts("");

	printf("[*]	source\t\t: ");
	for(i = 0; i < 4; i++){
		printf("%d", ip->src_ip_addr[i]);
		if(i < 3)
			printf(".");
	}
	puts("");
}

void printTcpInfo(const tcp_struct *tcp)
{
	puts("");
	printf("[-]	[TCP_header]\n");

	printf("[*]	destination port\t: %d\n", tcp->dest_tcp_port);
	printf("[*]	source port\t\t: %d\n", tcp->src_tcp_port);
	puts("");

}

void printTcpData(const u_char * packet, int len)
{
	int i;
	puts("");
	printf("[-]	[TCP_Data]\n");

	puts("");
	if(len > 54)
		dumpcode(packet + 54, len - 54);
}

