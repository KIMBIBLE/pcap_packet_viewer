#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/in.h>


const int ETHERNET_TYPE_IPV4 = 0x0800;
const int ETHERNET_TYPE_ARP = 0x0806;
const int PROTOCOL_ID_TCP = 6;
const int PROTOCOL_ID_UDP = 17;

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

void printchar(const unsigned char c);
void dumpcode(const unsigned char *buff, int len);
void deEncapsulateEthernet(u_char *packet, ethernet_struct *eth);
void deEncapsulateIpv4(u_char *packet, ipv4_struct *ip);
void deEncapsulateTcp(u_char *packet, tcp_struct *tcp);
void deEncapsulateTcpData(u_char *packet);


void printPacketInfo(u_char *packet, int len);
void printEthernetInfo(const ethernet_struct *eth);
void printIpv4Info(const ipv4_struct *ip);
void printTcpInfo(const tcp_struct *tcp);
void printTcpData(const u_char * packet, int len);

int main(int argc, char *argv[])
	{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	unsigned int packet_number = 0;
	u_char *packet_buf;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	puts("waiting for packet received from 80 port");

	/* Grab a packet */
	while(pcap_next_ex(handle, &header, &packet) != -1)
	{
		if(!header->len)
			continue;

		packet_buf = (u_char *)malloc(header->len);
		memcpy(packet_buf, packet, header->len);
		printf("-------packet Number : %d-------\n", packet_number);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header->len);
		dumpcode(packet_buf, header->len);
		printPacketInfo(packet_buf, header->len);
		printf("--------------------------------\n");
		packet_number++;
		puts("");
		free(packet_buf);
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}


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
		printf("%02x\n", ethernet.ethernet_type);
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
		printf("udp\n");
		return;
	}
	else{
		printf("%02x\n", ipv4.protocol_id);
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

void printchar(const unsigned char c)
{
	if(isprint(c))
		printf("%c", c);
	else
		printf(".");
}

void dumpcode(const unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", buf[i]);

		if (i % 16 - 15 == 0)
		{
			int j;
			printf("  ");
			for (j = i - 15; j <= i; j++)
				printchar(buf[j]);
			printf("\n");
		}
	}

	if (i % 16 != 0)
	{
		int j;
		int spaces = (len - i + 16 - i % 16) * 3 + 2;
		for (j = 0; j < spaces; j++)
			printf(" ");

		for (j = i - i % 16; j < len; j++)
			printchar(buf[j]);
	}
	printf("\n");
}

