/* Copyright © 2018 James Sung. All rights reserved. */
// usage: ./pcap_test <interface>

#include "functions.h"


char divisor[] = "*******************************************************************";


int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return -1;
	}

	char   *dev = argv[1];
	char    errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	//pcap_t *handle = pcap_open_offline("path/to/pcap/file", errbuf);
	// toggle `handle` to use either real-time capturing or existing pcap file

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);

		return -1;
	}

	printf("[+] Receiving packets...\n\n");

	while (true)
	{
		struct pcap_pkthdr *header;
		const uint8_t      *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		
		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { break; }
		
		struct libnet_ethernet_hdr *PCKT_ETH_HDR = (struct libnet_ethernet_hdr *)packet;

		uint16_t PCKT_ETHERTYPE = ntohs(PCKT_ETH_HDR->ether_type);

		uint16_t PCKT_IPPROTO;

		uint8_t PCKT_PRINTBASE;
		uint8_t PCKT_DATAOFFSET;
		uint8_t PCKT_DATALEN;

		// non TCP/IP packets omitted from print
		if (PCKT_ETHERTYPE != ETHERTYPE_IP) { continue; }
		
		struct libnet_ipv4_hdr *PCKT_IP_HDR = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

		PCKT_IPPROTO = PCKT_IP_HDR->ip_p; //printf("ipproto: 0x%02x\n", PCKT_IPPROTO);
		
		if (PCKT_IPPROTO != IPPROTO_TCP) { continue; }
	
		struct libnet_tcp_hdr *PCKT_TCP_HDR = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (PCKT_IP_HDR->ip_hl << 2));
	
		PCKT_DATAOFFSET = sizeof(struct libnet_ethernet_hdr) + (PCKT_IP_HDR->ip_hl << 2) + (PCKT_TCP_HDR->th_off << 2);
		PCKT_PRINTBASE = (PCKT_DATAOFFSET >> 4) << 4;
		PCKT_DATALEN = ntohs(PCKT_IP_HDR->ip_len) - (PCKT_IP_HDR->ip_hl << 2) - (PCKT_TCP_HDR->th_off << 2);

		printf("%s\n", divisor);
		
		printf("<%u bytes captured>\n\n", header->caplen);

		print_eth_info(PCKT_ETH_HDR); puts("");
		print_ip_info(PCKT_IP_HDR); puts("");
		print_tcp_info(PCKT_TCP_HDR); puts("");
		print_data_info(packet, PCKT_PRINTBASE, PCKT_DATAOFFSET, PCKT_DATALEN); puts("");

		printf("%s\n", divisor);
	}

	printf("[*] Program exiting...\n");

	return 0;
}

