/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"

void usage(void)
{
	printf("[-] Syntax: ./pcap_test <interface>\n");
	printf("[-] Sample: ./pcap_test wlan0\n");
	
	return;
}

void print_mac_addr(uint8_t *mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return;
}

void print_eth_info(struct libnet_ethernet_hdr *PCKT_ETH_HDR)
{
	printf("[Source      MAC Address] "); print_mac_addr(PCKT_ETH_HDR->ether_shost);
	printf("[Destination MAC Address] "); print_mac_addr(PCKT_ETH_HDR->ether_dhost);

	return;
}

void print_ip_addr(struct in_addr ip)
{
	printf("%s\n", inet_ntoa(ip));

	return;
}

void print_ip_info(struct libnet_ipv4_hdr *PCKT_IP_HDR)
{
	printf("[Source      IP  Address] "); print_ip_addr(PCKT_IP_HDR->ip_src);
	printf("[Destination IP  Address] "); print_ip_addr(PCKT_IP_HDR->ip_dst);
	
	return;
}

void print_port_number(uint16_t port)
{
	printf("%5d\n", ntohs(port));

	return;
}

void print_tcp_info(struct libnet_tcp_hdr *PCKT_TCP_HDR)
{
	printf("[Source      TCP  Port #] "); print_port_number(PCKT_TCP_HDR->th_sport);
	printf("[Destination TCP  Port #] "); print_port_number(PCKT_TCP_HDR->th_dport);

	return;
}

void print_data_info(const uint8_t *packet, uint8_t PCKT_PRINTBASE, uint8_t PCKT_DATAOFFSET, uint8_t PCKT_DATALEN)
{
	printf("[Data (up to 32 bytes displayed)]\n");
	for (int i = PCKT_PRINTBASE; i < (PCKT_DATAOFFSET + 32) && (i < PCKT_DATAOFFSET + PCKT_DATALEN); i++)
	{
		if (i < PCKT_DATAOFFSET) { printf("-- ");}
		else { printf("%02x ", packet[i]); }

		if (i % 16 == 7) { printf(" "); }
		if (i % 16 == 15) { printf("\n"); }
	}

	return;
}

