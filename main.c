#include <pcap/pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <string.h>


const int ETHERNET_TYPE_IPV4 = 0x0800;
const int ETHERNET_TYPE_ARP = 0x0806;

typedef struct ethernet_struct{
	u_char dest_addr_mac[6];
	u_char src_addr_mac[6];
	int ethernet_type;
}ethernet_struct;



void printchar(const unsigned char c);
void dumpcode(const unsigned char *buff, int len);
int deEncapsulateEthernet(const u_char *packet, ethernet_struct *eth);
void deEncapsulateIpv4();
void deEncapsulateTcp();
void deEncapsulateUdp();

void printPacketInfo(const u_char *packet);
void printEthernetInfo(const ethernet_struct *eth);

int main(int argc, char *argv[])
	{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	unsigned int packet_number = 0;

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
	/* Grab a packet */
	while(pcap_next_ex(handle, &header, &packet) >= 0)
	{
		printf("packet Number : %d\n", packet_number);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header->len);
		dumpcode(packet, header->len);
		printPacketInfo(packet);
		packet_number++;
		puts("");
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}


void printPacketInfo(const u_char *packet)
{
	int e_type = 0;
	ethernet_struct ethernet;
	e_type = deEncapsulateEthernet(packet, &ethernet);

	if(e_type == ETHERNET_TYPE_IPV4)
		printEthernetInfo(&ethernet);
	else if(e_type == ETHERNET_TYPE_ARP)
		printf("arp packet\n");
	else{;}
	
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
	for(i = 7; i < 13; i++){
		printf("%02x", eth->dest_addr_mac[i]);
		if(i < 12)
			printf(":");
	}
	puts("");
}

int deEncapsulateEthernet(const u_char *packet, ethernet_struct *eth)
{
	memcpy(eth->dest_addr_mac, packet, 6);
	return (int)packet[12] * 0x100 + packet[13];;
	
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

