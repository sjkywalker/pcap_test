/* Copyright © 2018 James Sung. All rights reserved. */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>


extern char divisor[];


void usage(void);

void print_mac_addr(uint8_t *mac);
void print_eth_info(struct libnet_ethernet_hdr *PCKT_ETH_HDR);

void print_ip_addr(struct in_addr ip);
void print_ip_info(struct libnet_ipv4_hdr *PCKT_IP_HDR);

void print_port_number(uint16_t port);
void print_tcp_info(struct libnet_tcp_hdr *PCKT_TCP_HDR);

void print_data_info(const uint8_t *packet, uint8_t PCKT_PRINTBASE, uint8_t PCKT_DATAOFFSET, uint8_t PCKT_DATALEN);

