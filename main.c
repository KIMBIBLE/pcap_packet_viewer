#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "dumpcode.h"
#include "deEncapsulate.h"
#include "data_type.h"
#include "print_packet.h"

const int ETHERNET_TYPE_IPV4 = 0x0800;
const int ETHERNET_TYPE_ARP = 0x0806;
const int PROTOCOL_ID_TCP = 6;
const int PROTOCOL_ID_UDP = 17;

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


